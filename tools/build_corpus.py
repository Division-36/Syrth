"""Multi-source vulnerability corpus builder.

Design constraints, derived from the failure of the v0 corpus:

1. **Every record must be traceable.** Each record carries the advisory id, the
   fix commit SHA, the file path, the function name, and the extraction method.
   A record whose provenance cannot be reconstructed is discarded, not shipped.

2. **The vulnerable revision must actually contain the sink.** The v0 corpus
   labelled every function touched by a fix commit, which produced a 1.7x
   inflation: at most one function per commit is the security fix, the rest are
   refactors. Here a function is only accepted as a positive if its pre-fix
   source contains a call from the labelled vulnerability class.

3. **The patch must be real.** A record is only accepted if the post-fix revision
   of the same function differs. A "fix" that does not change the function is a
   metadata error, not a vulnerability.

4. **Grouping is by advisory, never by function.** One CVE yields one group
   containing all its functions and all their patched counterparts, so a grouped
   split cannot straddle a vulnerability.

5. **Sources are unioned, not chained.** GHSA, NVD and OSV each contribute; a
   record is deduplicated on ``(repo, commit, file, function, cwe)``.

6. **Everything is bounded.** Page counts, clone sizes, per-request timeouts and
   the GitHub rate budget are parameters with defaults, and the builder records
   what it skipped and why.

This module never executes analysed or downloaded code. Repositories are read
through ``git show`` against a local clone; nothing is imported or run.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path

from syrth.registry import (
    CWE_TO_CATEGORY,
    SINK_SPECS,
    Bindings,
    SinkSpec,
    amplifier_for,
    canonical_sink,
)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

GITHUB_API = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/query"
CVE_LIST = "https://cveawg.mitre.org/api"

DISK_FLOOR_DEFAULT = 1024 ** 3

USER_AGENT = "syrth-corpus/1.0 (+https://github.com/Division-36/Syrth)"

#: Classes this project can reason about. Anything else is dropped, because a
#: label the analyser cannot produce is a label it cannot be measured against.
#:
#: The mapping is **derived from ``syrth.registry``**, not duplicated here. An
#: earlier copy of this table in the builder was a second source of truth and it
#: drifted: it treated a bare ``load`` as unsafe deserialisation, so keras's
#: ``load_data`` — which calls ``numpy.load`` on a dataset file — was labelled
#: CWE-502. SYRTH's own registry already encodes the rule this got wrong, as
#: invariant 3: short ambiguous names are sinks only when bound from a dangerous
#: module. Deriving from it makes the corpus and the product agree on what a
#: class *means*, which is the only way a corpus can measure the product.
CWE_TO_CATEGORY = CWE_TO_CATEGORY

#: Classes with at least one modelled sink, for cheap membership checks.
IN_SCOPE: frozenset[str] = frozenset(CWE_TO_CATEGORY)


#: Repositories harvested. Chosen for security-fix history and Python share.
#:
#: The third field is the **PyPI distribution name**, which is not always the
#: clone name and is what the GHSA ``affects`` filter matches on. ``Jinja2`` vs
#: ``jinja`` and ``Pillow`` vs ``pillow`` are the difference between 70
#: advisories and none at all.
#:
#: Repositories are cloned lazily, so listing a package here costs one API call
#: and nothing more unless it turns out to own an in-scope fix commit.
DEFAULT_REPOS = [
    ("django", "https://github.com/django/django.git", "Django"),
    ("flask", "https://github.com/pallets/flask.git", "Flask"),
    ("werkzeug", "https://github.com/pallets/werkzeug.git", "Werkzeug"),
    ("jinja", "https://github.com/pallets/jinja.git", "Jinja2"),
    ("flask-login", "https://github.com/maxcountryman/flask-login.git", "Flask-Login"),
    ("requests", "https://github.com/psf/requests.git", "requests"),
    ("urllib3", "https://github.com/urllib3/urllib3.git", "urllib3"),
    ("yarl", "https://github.com/aio-libs/yarl.git", "yarl"),
    ("sqlalchemy", "https://github.com/sqlalchemy/sqlalchemy.git", "SQLAlchemy"),
    ("celery", "https://github.com/celery/celery.git", "celery"),
    ("tornado", "https://github.com/tornadoweb/tornado.git", "tornado"),
    ("aiohttp", "https://github.com/aio-libs/aiohttp.git", "aiohttp"),
    ("pillow", "https://github.com/python-pillow/Pillow.git", "Pillow"),
    ("paramiko", "https://github.com/paramiko/paramiko.git", "paramiko"),
    ("pyyaml", "https://github.com/yaml/pyyaml.git", "PyYAML"),
    # Web frameworks and templating
    ("django-rest-framework", "https://github.com/encode/django-rest-framework.git", "djangorestframework"),
    ("flask-restful", "https://github.com/flask-restful/flask-restful.git", "Flask-RESTful"),
    ("quart", "https://github.com/pallets/quart.git", "Quart"),
    ("bottle", "https://github.com/bottlepy/bottle.git", "bottle"),
    ("cherrypy", "https://github.com/cherrypy/cherrypy.git", "CherryPy"),
    ("starlette", "https://github.com/encode/starlette.git", "starlette"),
    ("fastapi", "https://github.com/fastapi/fastapi.git", "fastapi"),
    ("sanic", "https://github.com/sanic-org/sanic.git", "sanic"),
    ("pyramid", "https://github.com/Pylons/pyramid.git", "pyramid"),
    ("webob", "https://github.com/Pylons/webob.git", "WebOb"),
    ("markupsafe", "https://github.com/pallets/markupsafe.git", "MarkupSafe"),
    ("itsdangerous", "https://github.com/pallets/itsdangerous.git", "itsdangerous"),
    # HTTP clients and networking
    ("httpx", "https://github.com/encode/httpx.git", "httpx"),
    ("httpcore", "https://github.com/encode/httpcore.git", "httpcore"),
    ("h11", "https://github.com/python-hyper/h11.git", "h11"),
    ("h2", "https://github.com/python-hyper/h2.git", "h2"),
    ("twisted", "https://github.com/twisted/twisted.git", "Twisted"),
    ("zope-interface", "https://github.com/zopefoundation/zope-interface.git", "zope.interface"),
    ("uritemplate", "https://github.com/python-hyper/uritemplate.git", "uritemplate"),
    ("websocket-client", "https://github.com/websocket-client/websocket-client.git", "websocket-client"),
    ("dnspython", "https://github.com/rthalley/dnspython.git", "dnspython"),
    ("cryptography", "https://github.com/pyca/cryptography.git", "cryptography"),
    ("pynacl", "https://github.com/pyca/pynacl.git", "PyNaCl"),
    ("bcrypt", "https://github.com/pyca/bcrypt.git", "bcrypt"),
    ("passlib", "https://github.com/python-ldap/python-passlib.git", "passlib"),
    ("itsdangerous-alt", "https://github.com/pallets/itsdangerous.git", "itsdangerous"),
    # Serialisation, parsing, compression
    ("pyyaml-lib", "https://github.com/yaml/pyyaml.git", "PyYAML"),
    ("lxml", "https://github.com/lxml/lxml.git", "lxml"),
    ("pillow-simd", "https://github.com/python-pillow/Pillow.git", "Pillow"),
    ("defusedxml", "https://github.com/tiran/defusedxml.git", "defusedxml"),
    ("xmltodict", "https://github.com/martinblech/xmltodict.git", "xmltodict"),
    ("openpyxl", "https://github.com/theorchard/openpyxl.git", "openpyxl"),
    ("xlrd", "https://github.com/python-excel/xlrd.git", "xlrd"),
    ("xlwt", "https://github.com/jan/janitor.git", "xlwt"),
    ("html5lib", "https://github.com/html5lib/html5lib-python.git", "html5lib"),
    ("bleach", "https://github.com/mozilla/bleach.git", "bleach"),
    ("markdown", "https://github.com/Python-Markdown/markdown.git", "Markdown"),
    ("mistune", "https://github.com/lepture/mistune.git", "mistune"),
    ("docutils", "https://github.com/docutils/docutils.git", "docutils"),
    ("pygments", "https://github.com/pygments/pygments.git", "Pygments"),
    ("nbconvert", "https://github.com/jupyter/nbconvert.git", "nbconvert"),
    ("nbformat", "https://github.com/jupyter/nbformat.git", "nbformat"),
    ("joblib", "https://github.com/joblib/joblib.git", "joblib"),
    ("dill", "https://github.com/uqfoundation/dill.git", "dill"),
    ("cloudpickle", "https://github.com/cloudpipe/cloudpickle.git", "cloudpickle"),
    ("pandas", "https://github.com/pandas-dev/pandas.git", "pandas"),
    ("numpy", "https://github.com/numpy/numpy.git", "numpy"),
    ("scipy", "https://github.com/scipy/scipy.git", "scipy"),
    ("matplotlib", "https://github.com/matplotlib/matplotlib.git", "matplotlib"),
    ("scikit-learn", "https://github.com/scikit-learn/scikit-learn.git", "scikit-learn"),
    ("scikit-image", "https://github.com/scikit-image/scikit-image.git", "scikit-image"),
    ("pillow-legacy", "https://github.com/python-pillow/Pillow.git", "Pillow"),
    ("torch", "https://github.com/pytorch/pytorch.git", "torch"),
    ("tensorflow", "https://github.com/tensorflow/tensorflow.git", "tensorflow"),
    ("keras", "https://github.com/keras-team/keras.git", "keras"),
    ("flask-wtf", "https://github.com/wtforms/flask-wtf.git", "Flask-WTF"),
    ("wtforms", "https://github.com/wtforms/wtforms.git", "WTForms"),
    ("sqlparse", "https://github.com/andialbrecht/sqlparse.git", "sqlparse"),
    ("alembic", "https://github.com/sqlalchemy/alembic.git", "alembic"),
    ("psycopg2", "https://github.com/psycopg/psycopg2.git", "psycopg2-binary"),
    ("pymysql", "https://github.com/PyMySQL/PyMySQL.git", "PyMySQL"),
    ("mysqlclient", "https://github.com/PyMySQL/mysqlclient.git", "mysqlclient"),
    ("pymongo", "https://github.com/mongodb/mongo-python-driver.git", "pymongo"),
    ("redis", "https://github.com/redis/redis-py.git", "redis"),
    ("boto3", "https://github.com/boto/boto3.git", "boto3"),
    ("botocore", "https://github.com/boto/botocore.git", "botocore"),
    ("google-cloud-storage", "https://github.com/googleapis/python-storage.git", "google-cloud-storage"),
    ("oauthlib", "https://github.com/oauthlib/oauthlib.git", "oauthlib"),
    ("requests-oauthlib", "https://github.com/requests/requests-oauthlib.git", "requests-oauthlib"),
    ("authlib", "https://github.com/lepture/authlib.git", "authlib"),
    ("social-auth", "https://github.com/python-social-auth/social-core.git", "social-auth-core"),
    ("jwt", "https://github.com/jpadilla/pyjwt.git", "PyJWT"),
    ("cryptg", "https://github.com/pyca/cryptography.git", "cryptography"),
    ("ansible", "https://github.com/ansible/ansible.git", "ansible"),
    ("salt", "https://github.com/saltstack/salt.git", "salt"),
    ("fabric", "https://github.com/fabric/fabric.git", "fabric"),
    ("invoke", "https://github.com/pyinvoke/invoke.git", "invoke"),
    ("plumbum", "https://github.com/tomerfiliba/plumbum.git", "plumbum"),
    ("docker", "https://github.com/docker/docker-py.git", "docker"),
    ("kubernetes", "https://github.com/kubernetes-client/python.git", "kubernetes"),
    ("openshift", "https://github.com/openshift/openshift-restclient-python.git", "openshift"),
    ("jinja-alt", "https://github.com/pallets/jinja.git", "Jinja2"),
    ("py", "https://github.com/pytest-dev/py.git", "py"),
    ("pytest", "https://github.com/pytest-dev/pytest.git", "pytest"),
    ("coverage", "https://github.com/nedbat/coveragepy.git", "coverage"),
    ("virtualenv", "https://github.com/pypa/virtualenv.git", "virtualenv"),
    ("pip", "https://github.com/pypa/pip.git", "pip"),
    ("setuptools", "https://github.com/pypa/setuptools.git", "setuptools"),
    ("wheel", "https://github.com/pypa/wheel.git", "wheel"),
    ("build", "https://github.com/pypa/build.git", "build"),
    ("twine", "https://github.com/pypa/twine.git", "twine"),
    ("packaging", "https://github.com/pypa/packaging.git", "packaging"),
    ("platformdirs", "https://github.com/platformdirs/platformdirs.git", "platformdirs"),
    ("filelock", "https://github.com/tox-dev/filelock.git", "filelock"),
    ("cffi", "https://github.com/python-cffi/cffi.git", "cffi"),
    ("cython", "https://github.com/cython/cython.git", "Cython"),
    ("pyinstaller", "https://github.com/pyinstaller/pyinstaller.git", "pyinstaller"),
    ("zmq", "https://github.com/zeromq/pyzmq.git", "pyzmq"),
    ("kafka", "https://github.com/dpkp/kafka-python.git", "kafka-python"),
    ("confluent-kafka", "https://github.com/confluentinc/confluent-kafka-python.git", "confluent-kafka"),
    ("pika", "https://github.com/pika/pika.git", "pika"),
    ("elasticsearch", "https://github.com/elastic/elasticsearch-py.git", "elasticsearch"),
    ("prometheus", "https://github.com/prometheus/client_python.git", "prometheus-client"),
    ("sentry-sdk", "https://github.com/getsentry/sentry-python.git", "sentry-sdk"),
    ("opentelemetry", "https://github.com/open-telemetry/opentelemetry-python.git", "opentelemetry-api"),
    ("structlog", "https://github.com/hynek/structlog.git", "structlog"),
    ("loguru", "https://github.com/Delgan/loguru.git", "loguru"),
    ("tenacity", "https://github.com/jd/tenacity.git", "tenacity"),
    ("click", "https://github.com/pallets/click.git", "click"),
    ("typer", "https://github.com/fastapi/typer.git", "typer"),
    ("rich", "https://github.com/Textualize/rich.git", "rich"),
    ("colorama", "https://github.com/tartley/colorama.git", "colorama"),
    ("tqdm", "https://github.com/tqdm/tqdm.git", "tqdm"),
    ("prompt-toolkit", "https://github.com/prompt-toolkit/python-prompt-toolkit.git", "prompt_toolkit"),
    ("ipython", "https://github.com/ipython/ipython.git", "ipython"),
    ("jupyter-client", "https://github.com/jupyter/jupyter_client.git", "jupyter_client"),
    ("notebook", "https://github.com/jupyter/notebook.git", "notebook"),
    ("bokeh", "https://github.com/bokeh/bokeh.git", "bokeh"),
    ("plotly", "https://github.com/plotly/plotly.py.git", "plotly"),
    ("dash", "https://github.com/plotly/dash.git", "dash"),
    ("streamlit", "https://github.com/streamlit/streamlit.git", "streamlit"),
    ("gradio", "https://github.com/gradio-app/gradio.git", "gradio"),
    ("transformers", "https://github.com/huggingface/transformers.git", "transformers"),
    ("datasets", "https://github.com/huggingface/datasets.git", "datasets"),
    ("tokenizers", "https://github.com/huggingface/tokenizers.git", "tokenizers"),
    ("safetensors", "https://github.com/huggingface/safetensors.git", "safetensors"),
    ("accelerate", "https://github.com/huggingface/accelerate.git", "accelerate"),
    ("langchain", "https://github.com/langchain-ai/langchain.git", "langchain"),
    ("langchain-core", "https://github.com/langchain-ai/langchain.git", "langchain-core"),
    ("llama-index", "https://github.com/run-llama/llama_index.git", "llama-index"),
    ("chromadb", "https://github.com/chroma-core/chroma.git", "chromadb"),
    ("qdrant-client", "https://github.com/qdrant/qdrant-client.git", "qdrant-client"),
    ("pinecone-client", "https://github.com/pinecone-io/pinecone-python-client.git", "pinecone-client"),
    ("weaviate-client", "https://github.com/weaviate/weaviate-python-client.git", "weaviate-client"),
    ("supabase", "https://github.com/supabase/supabase-py.git", "supabase"),
    ("firebase-admin", "https://github.com/firebase/firebase-admin-python.git", "firebase-admin"),
    ("twilio", "https://github.com/twilio/twilio-python.git", "twilio"),
    ("sendgrid", "https://github.com/sendgrid/sendgrid-python.git", "sendgrid"),
    ("stripe", "https://github.com/stripe/stripe-python.git", "stripe"),
    ("slack-sdk", "https://github.com/slackapi/python-slack-sdk.git", "slack-sdk"),
    ("atlassian-python-api", "https://github.com/atlassian-api/atlassian-python-api.git", "atlassian-python-api"),
    ("jira", "https://github.com/pycontribs/jira.git", "jira"),
    ("apache-airflow", "https://github.com/apache/airflow.git", "apache-airflow"),
    ("luigi", "https://github.com/spotify/luigi.git", "luigi"),
    ("prefect", "https://github.com/PrefectHQ/prefect.git", "prefect"),
    ("dagster", "https://github.com/dagster-io/dagster.git", "dagster"),
    ("mlflow", "https://github.com/mlflow/mlflow.git", "mlflow"),
    ("wandb", "https://github.com/wandb/wandb.git", "wandb"),
    ("ray", "https://github.com/ray-project/ray.git", "ray"),
    ("dask", "https://github.com/dask/dask.git", "dask"),
    ("modin", "https://github.com/modin-project/modin.git", "modin"),
    ("networkx", "https://github.com/networkx/networkx.git", "networkx"),
    ("sympy", "https://github.com/sympy/sympy.git", "sympy"),
    ("mpmath", "https://github.com/mpmath/mpmath.git", "mpmath"),
    ("astropy", "https://github.com/astropy/astropy.git", "astropy"),
    ("biopython", "https://github.com/biopython/biopython.git", "biopython"),
    ("rdkit", "https://github.com/rdkit/rdkit.git", "rdkit"),
    ("pymol", "https://github.com/cgohlke/pymol-open-source.git", "PyMOL"),
    ("wxpython", "https://github.com/wxWidgets/wxPython.git", "wxPython"),
    ("pyqt", "https://github.com/dirkjanp/PyQt5.git", "PyQt5"),
    ("kivy", "https://github.com/kivy/kivy.git", "kivy"),
    ("pygame", "https://github.com/pygame/pygame.git", "pygame"),
    ("pyaudio", "https://github.com/intxcc/pyaudio.git", "PyAudio"),
    ("soundfile", "https://github.com/python-soundfile/soundfile.git", "soundfile"),
    ("librosa", "https://github.com/librosa/librosa.git", "librosa"),
    ("music21", "https://github.com/cuthbertLab/music21.git", "music21"),
    ("pillow-extra", "https://github.com/python-pillow/Pillow.git", "Pillow"),
    ("reportlab", "https://github.com/MrBitByte/reportlab.git", "reportlab"),
    ("weasyprint", "https://github.com/Kozea/WeasyPrint.git", "weasyprint"),
    ("pypdf", "https://github.com/py-pdf/pypdf.git", "pypdf"),
    ("pypdf2", "https://github.com/py-pdf/pypdf.git", "PyPDF2"),
    ("pdfminer", "https://github.com/pdfminer/pdfminer.six.git", "pdfminer.six"),
    ("fitz", "https://github.com/pymupdf/PyMuPDF.git", "PyMuPDF"),
    ("python-docx", "https://github.com/python-openxml/python-docx.git", "python-docx"),
    ("python-pptx", "https://github.com/scanny/python-pptx.git", "python-pptx"),
    ("beautifulsoup", "https://github.com/wention/BeautifulSoup4.git", "beautifulsoup4"),
    ("lxml-html", "https://github.com/lxml/lxml.git", "lxml"),
    ("cssselect", "https://github.com/scrapy/cssselect.git", "cssselect"),
    ("scrapy", "https://github.com/scrapy/scrapy.git", "Scrapy"),
    ("selenium", "https://github.com/SeleniumHQ/selenium.git", "selenium"),
    ("playwright-python", "https://github.com/microsoft/playwright-python.git", "playwright"),
    ("pytest-cov", "https://github.com/pytest-dev/pytest-cov.git", "pytest-cov"),
    ("hypothesis", "https://github.com/HypothesisWorks/hypothesis.git", "hypothesis"),
    ("faker", "https://github.com/joke2k/faker.git", "Faker"),
    ("responses", "https://github.com/getsentry/responses.git", "responses"),
    ("freezegun", "https://github.com/spulec/freezegun.git", "freezegun"),
    ("vcrpy", "https://github.com/kevin1024/vcrpy.git", "vcrpy"),
]


def _dedupe_repos(entries: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """One entry per repository URL, keeping the first (canonical) name.

    Several packages are commonly published from one repository. Listing an
    alias for each would spend an extra API call per alias and, worse, would
    make ``_candidate_repos`` report the same project under four different names
    so the corpus would list Pillow four times with four unrelated record keys.
    """
    seen_urls: set[str] = set()
    out: list[tuple[str, str, str]] = []
    for name, url, distribution in entries:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        out.append((name, url, distribution))
    return out


DEFAULT_REPOS = _dedupe_repos(DEFAULT_REPOS)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


class RateBudget:
    """Tracks the GitHub rate budget so a run cannot exhaust it silently.

    Thread-safe, because collection runs concurrently: without a lock two
    workers can both observe a unit and overshoot the floor.
    """

    def __init__(self, limit: int, floor: int = 200):
        self.limit = limit
        self.remaining = limit
        self.floor = floor
        self.used = 0
        self._lock = threading.Lock()

    def take(self) -> bool:
        """Consume one unit. False when the budget is exhausted."""
        with self._lock:
            if self.remaining <= self.floor:
                return False
            self.remaining -= 1
            self.used += 1
            return True

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "limit": self.limit,
                "remaining": self.remaining,
                "used": self.used,
                "exhausted": self.remaining <= self.floor,
            }


class Fetcher:
    """HTTP with retry, backoff and an explicit rate budget.

    Safe to share across threads: collection is fanned out, and the mutable
    state here (backoff, error log) is guarded.
    """

    def __init__(self, token: str | None, budget: RateBudget, timeout: int = 45):
        self.token = token
        self.budget = budget
        self.timeout = timeout
        self.backoff = 1.0
        self.errors: list[dict] = []
        self._lock = threading.Lock()

    def _note_error(self, url: str, error: str) -> None:
        with self._lock:
            self.errors.append({"url": url, "error": error})

    def _headers(self) -> dict:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def get(self, url: str, *, budgeted: bool = True) -> object | None:
        for attempt in range(4):
            if budgeted and not self.budget.take():
                return None
            try:
                request = urllib.request.Request(url, headers=self._headers())
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                with self._lock:
                    self.backoff = 1.0
                return json.loads(raw.decode("utf-8", "replace"))
            except urllib.error.HTTPError as exc:
                if exc.code == 403:
                    remaining = 0
                    try:
                        remaining = int(exc.headers.get("X-RateLimit-Remaining", "0"))
                    except (TypeError, ValueError):
                        pass
                    self.budget.remaining = min(self.budget.remaining, remaining)
                    self._note_error(url, f"HTTP {exc.code}")
                    return None
                if exc.code in (429, 502, 503) and attempt < 3:
                    time.sleep(min(self.backoff, 8))
                    self.backoff *= 2
                    continue
                self._note_error(url, f"HTTP {exc.code}")
                return None
            except Exception as exc:  # noqa: BLE001 - network shapes vary
                if attempt < 3:
                    time.sleep(min(self.backoff, 8))
                    self.backoff *= 2
                    continue
                self._note_error(url, type(exc).__name__)
                return None
        return None

    def post(self, url: str, payload: dict, *, budgeted: bool = False) -> object | None:
        body = json.dumps(payload).encode("utf-8")
        for attempt in range(4):
            if budgeted and not self.budget.take():
                return None
            try:
                request = urllib.request.Request(
                    url, data=body,
                    headers={**self._headers(), "Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                self.backoff = 1.0
                return json.loads(raw.decode("utf-8", "replace"))
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 502, 503) and attempt < 3:
                    time.sleep(self.backoff)
                    self.backoff *= 2
                    continue
                self.errors.append({"url": url, "error": f"HTTP {exc.code}"})
                return None
            except Exception as exc:  # noqa: BLE001
                if attempt < 3:
                    time.sleep(self.backoff)
                    self.backoff *= 2
                    continue
                self.errors.append({"url": url, "error": type(exc).__name__})
                return None
        return None


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------


@dataclass
class Advisory:
    """One vulnerability, from any source, normalised."""

    advisory_id: str
    source: str
    cwes: tuple[str, ...]
    summary: str
    repo_hint: str
    fix_commits: tuple[str, ...]
    package: str = ""

    def in_scope(self) -> tuple[str, ...]:
        return tuple(c for c in self.cwes if c in IN_SCOPE)


@dataclass
class Record:
    """One labelled function, with full provenance.

    Two identifiers are needed and they are not interchangeable:

    * ``pair_id`` identifies the **pair** — one function, one class, one fix.
      This is what a consumer joins on to recover the vulnerable and patched
      sides.
    * ``group`` identifies the **advisory**, and is the unit a train/test split
      must keep intact.

    Both distinctions are load-bearing. One advisory frequently fixes several
    functions — ``django/utils/archive.py`` patches both ``TarArchive.extract``
    and ``ZipArchive.extract`` — and two advisories frequently share one commit:
    keras ``d338a452`` carries both a path-traversal and a deserialisation fix.
    A single combined key made those pairs unpairable, and using the advisory as
    the pair key instead would leak the same fix across a train/test boundary.
    """

    pair_id: str
    group: str
    source: str
    label: str
    cwe: str
    repo: str
    advisory_id: str
    commit: str
    file: str
    function: str
    qualname: str
    kind: str
    origin_source: str
    sink_call: str
    #: ``direct-sink`` -- the labelled source itself calls a sink of its class.
    #: ``module-proximity`` -- it only produces a value for a sink elsewhere in
    #: the same module. A real, disclosed weakness, kept separate so no metric
    #: can quietly mix the two.
    evidence: str = ""
    #: Qualified sink this record's function produced a value for, when the
    #: evidence is `module-proximity`. Empty otherwise.
    module_sink: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


@dataclass
class BuildStats:
    """Everything the run did, including what it declined to do."""

    started: str = ""
    advisories_seen: int = 0
    advisories_in_scope: int = 0
    repos_cloned: int = 0
    commits_inspected: int = 0
    candidates: int = 0
    accepted_positive: int = 0
    accepted_negative: int = 0
    rejected_no_sink: int = 0
    rejected_no_change: int = 0
    rejected_unparseable: int = 0
    rejected_out_of_scope: int = 0
    deduplicated: int = 0
    direct_sink: int = 0
    module_proximity: int = 0
    evidence_tiers: dict = field(default_factory=dict)
    classes_covered: list[str] = field(default_factory=list)
    repos_covered: dict[str, int] = field(default_factory=dict)
    rate: dict = field(default_factory=dict)
    errors: list[dict] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Source adapters
# --------------------------------------------------------------------------


def ghsa_advisories_for_packages(
    fetcher: Fetcher,
    distributions: list[str],
    pages: int,
    ecosystem: str = "pip",
    workers: int = 8,
) -> list[Advisory]:
    """GitHub-reviewed advisories, queried **per affected package**.

    This is the primary GHSA strategy, and it replaces scanning the global
    ecosystem listing. The global listing is ordered by publication date across
    all ecosystems, so pip entries are a minority of every page: a scan of 1200
    advisories yielded 78 usable ones. Asking GHSA what it knows about one
    package instead returned 308 for the same 15 packages, a 4x gain for the
    same rate budget, and — more importantly — it spread the corpus across
    repos instead of concentrating it in whichever package happened to be
    published in most recently.

    ``affects`` matches the PyPI **distribution** name exactly, so callers must
    pass the real distribution name and not the clone name.

    Deduplication happens **after** the fan-out, not during it. Several
    distributions can name the same advisory (an OS package and a pip one), and
    deciding "have I seen this id" while workers are running is a check-then-set
    race that duplicates or drops entries depending on timing. Because
    ``_fan_out`` returns results in input order, a single ordered pass is both
    deterministic and race-free.
    """
    advisories: list[Advisory] = []
    wanted = _ECOSYSTEM_ALIASES.get(ecosystem.lower(), ecosystem.lower())

    def collect(distribution: str) -> list[Advisory]:
        """All pages for one distribution, newest first, then stop when empty."""
        local: list[Advisory] = []
        for page in range(1, pages + 1):
            url = (
                f"{GITHUB_API}/advisories?affects={urllib.parse.quote(distribution)}"
                f"&ecosystem={wanted}&per_page=100&type=reviewed"
                f"&sort=published&direction=desc&page={page}"
            )
            payload = fetcher.get(url)
            if not isinstance(payload, list):
                break
            if not payload:
                break
            for item in payload:
                advisory = _advisory_from_ghsa_item(item, wanted)
                if advisory is not None:
                    local.append(advisory)
        return local

    seen: set[str] = set()
    for found in _fan_out(collect, distributions, workers):
        for advisory in found:
            if advisory.advisory_id in seen:
                continue
            seen.add(advisory.advisory_id)
            advisories.append(advisory)
    return advisories


def _fan_out(function, items: list, workers: int) -> list:
    """Run ``function`` over ``items`` concurrently, preserving order.

    Collection is IO-bound and almost entirely latency: 192 distributions at
    ~1.3 s per request is 21 minutes serially, and that is the dominant cost of
    every run. Eight workers brings it to about three minutes.
    """
    if workers <= 1 or len(items) <= 1:
        return [function(item) for item in items]
    results: list = [None] * len(items)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(function, item): i for i, item in enumerate(items)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:  # noqa: BLE001 - one package must not kill the run
                results[index] = []
                print(f"      package failed: {type(exc).__name__}", flush=True)
    return results


def _advisory_from_ghsa_item(item: dict, ecosystem: str) -> Advisory | None:
    """Convert one GHSA advisory, or ``None`` if it is unusable.

    Defensive against the shape of GitHub's payload rather than trusting it:
    ``cwes`` entries are assumed to be mappings, ``references`` may be plain
    strings or objects depending on the endpoint, and either being malformed
    must drop this advisory rather than abort collection of the rest.
    """
    ghsa_id = item.get("ghsa_id") or ""
    if not ghsa_id:
        return None
    cwes = tuple(
        c.get("cwe_id") for c in (item.get("cwes") or [])
        if isinstance(c, dict) and c.get("cwe_id")
    )
    references = [
        r if isinstance(r, str) else (r or {}).get("url", "")
        for r in (item.get("references") or [])
    ]
    commits = tuple(
        dict.fromkeys(
            _commit_from_url(u) for u in references
            if "/commit/" in u and _commit_from_url(u)
        )
    )
    package, repo_hint = _package_and_repo(item, references)
    if ecosystem and _ecosystem_of(item) != ecosystem:
        return None
    return Advisory(
        advisory_id=ghsa_id,
        source="ghsa",
        cwes=cwes,
        summary=(item.get("summary") or "")[:300],
        repo_hint=repo_hint,
        fix_commits=commits,
        package=package,
    )


def ghsa_advisories(fetcher: Fetcher, pages: int, ecosystem: str | None) -> list[Advisory]:
    """GitHub-reviewed advisories.

    ``ecosystem`` filters on the advisory's *package* name, but the listing is
    ordered by publication date across all ecosystems, so on a recent page the
    filter can discard every entry and yield zero advisories while looking like
    a successful call. The filter is therefore applied only after collection,
    by ``package_matching``, and callers are expected to also use OSV, which
    returns fix commits more reliably.
    """
    found: list[Advisory] = []
    seen: set[str] = set()
    for page in range(1, pages + 1):
        url = (
            f"{GITHUB_API}/advisories?per_page=100&type=reviewed&page={page}"
            f"&sort=published&direction=desc"
        )
        payload = fetcher.get(url)
        if not isinstance(payload, list):
            break
        if not payload:
            break
        for item in payload:
            ghsa_id = item.get("ghsa_id") or ""
            if not ghsa_id or ghsa_id in seen:
                continue
            seen.add(ghsa_id)
            cwes = tuple(
                c.get("cwe_id") for c in (item.get("cwes") or [])
                if c.get("cwe_id")
            )
            references = [
                r if isinstance(r, str) else r.get("url", "")
                for r in (item.get("references") or [])
            ]
            commits = tuple(
                _commit_from_url(u) for u in references
                if "/commit/" in u and _commit_from_url(u)
            )
            package, repo_hint = _package_and_repo(item, references)
            # Filter on the ecosystem GitHub reports, not on the package name.
            # A recent page is mostly Go and npm; only the ``pip`` entries are
            # analysable, and dropping the rest here is what makes the source
            # usable at all.
            if ecosystem and _ecosystem_of(item) != _ECOSYSTEM_ALIASES.get(
                ecosystem.lower(), ecosystem.lower()
            ):
                continue
            found.append(
                Advisory(
                    advisory_id=ghsa_id,
                    source="ghsa",
                    cwes=cwes,
                    summary=(item.get("summary") or "")[:300],
                    repo_hint=repo_hint,
                    fix_commits=commits,
                    package=package,
                )
            )
    return found


def _ecosystem_of(item: dict) -> str:
    """Ecosystem of an advisory's primary package, as GitHub names it.

    GHSA calls PyPI ``pip``, not ``PyPI``. Filtering on the literal string
    ``PyPI`` matched nothing and silently reduced the source to zero advisories
    on a page where 37 were in scope.
    """
    for vulnerability in item.get("vulnerabilities") or []:
        ecosystem = ((vulnerability.get("package") or {}).get("ecosystem") or "").lower()
        if ecosystem:
            return ecosystem
    return ""


_ECOSYSTEM_ALIASES = {
    "pypi": "pip",
    "python": "pip",
    "pip": "pip",
}


def package_matches(package: str, ecosystem: str | None) -> bool:
    """Whether a package name belongs to the requested ecosystem."""
    if not ecosystem:
        return True
    wanted = _ECOSYSTEM_ALIASES.get(ecosystem.lower(), ecosystem.lower())
    return wanted == "pip"


def osv_advisories(
    fetcher: Fetcher, packages: list[str], workers: int = 8
) -> list[Advisory]:
    """OSV per package, fetched concurrently.

    OSV is the complement to GHSA: its entries carry fix commits that GHSA omits,
    and its GHSA-mirrored entries carry CWEs that OSV itself leaves empty.
    """

    def collect(package: str) -> list[Advisory]:
        payload = fetcher.post(
            OSV_API, {"package": {"name": package, "ecosystem": "PyPI"}}
        )
        if not isinstance(payload, dict):
            return []
        local: list[Advisory] = []
        for item in payload.get("vulns") or []:
            advisory_id = item.get("id") or ""
            if not advisory_id:
                continue
            database_specific = item.get("database_specific") or {}
            cwes = tuple(
                str(c) for c in (database_specific.get("cwe_ids") or [])
            )
            references = [
                r.get("url", "") for r in (item.get("references") or [])
                if isinstance(r, dict)
            ]
            commits = tuple(
                dict.fromkeys(
                    _commit_from_url(u) for u in references
                    if "/commit/" in u and _commit_from_url(u)
                )
            )
            local.append(
                Advisory(
                    advisory_id=advisory_id,
                    source="osv",
                    cwes=cwes,
                    summary=(item.get("summary") or "")[:300],
                    repo_hint="",
                    fix_commits=commits,
                    package=package,
                )
            )
        return local

    found: list[Advisory] = []
    for local in _fan_out(collect, packages, workers):
        found.extend(local)
    return found


def _commit_from_url(url: str) -> str:
    if "/commit/" not in url:
        return ""
    tail = url.rsplit("/", 1)[-1].split("?")[0].split("#")[0]
    return tail if re.fullmatch(r"[0-9a-fA-F]{7,40}", tail) else ""


def _package_and_repo(item: dict, references: list[str]) -> tuple[str, str]:
    package = ""
    repo = ""
    for vulnerability in item.get("vulnerabilities") or []:
        package = package or (vulnerability.get("package") or {}).get("name", "")
        repo = repo or (vulnerability.get("package") or {}).get("repository", "")
    if not repo:
        for url in references:
            match = re.search(r"github\.com/([^/]+/[^/]+)", url)
            if match:
                repo = match.group(1)
                if not package:
                    package = repo.rsplit("/", 1)[-1]
                break
    return package, repo


# --------------------------------------------------------------------------
# Repository access
# --------------------------------------------------------------------------


class RepoCache:
    """Local clones, reused across runs.

    Clones are **full by default**, with a partial fallback when disk is tight.

    The measured facts that decide this, rather than taste:

    * A partial clone fetches each blob on demand over the network, and that
      cost is **~6.5 s per blob whether it is read one ``git show`` at a time or
      batched through one ``git cat-file --batch``**. The fetch is negotiated
      per git invocation regardless, so batching only saves process spawns, not
      network. (An earlier measurement suggesting 0.02 s per blob was wrong: it
      had run after a prior step had already warmed those same blobs.)
    * A full clone pays that once. django is 45 MB and pillow 70 MB, so for most
      of the ecosystem the full clone *is* the cheap option.
    * But the drive here has **3.5 GB free**, and a few repositories
      (``apache-airflow``, ``pytorch``, ``tensorflow``) exceed that on their own.

    So: full clone while there is comfortable headroom, partial clone once the
    free space drops below the floor. ``read_blobs`` stays batched because it is
    never worse and saves one process per blob.
    """

    #: Specs per ``cat-file --batch`` call.
    BATCH = 64

    #: Free bytes a full clone must leave behind.
    DISK_FLOOR = 2 * 1024 ** 3

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _free_bytes(path: Path) -> int:
        try:
            return shutil.disk_usage(path).free
        except OSError:
            return DISK_FLOOR_DEFAULT

    def ensure(
        self, name: str, url: str, timeout: int = 3600, allow_full: bool = True
    ) -> Path | None:
        """Clone ``name`` if absent and return its path.

        ``allow_full`` is decided by the caller from the repository's **measured**
        size and the free disk, not from a hardcoded list. An earlier version kept
        a static ``HUGE`` set, which was a guess that went stale: ``apache-airflow``
        was forced partial while 11 GB sat free, and partial clones fetch blobs at
        ~6.5 s each, so one repository stalled the whole run. Measured sizes come
        from the GitHub API and cannot rot like a hand-maintained list.
        """
        destination = self.root / name
        if (destination / ".git").is_dir():
            return destination
        args = ["git", "clone", "--quiet"]
        if not allow_full:
            args += ["--filter=blob:none", "--no-checkout"]
        args += [url, str(destination)]
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=timeout)
        if result.returncode != 0 and allow_full:
            # Retry as a partial clone before giving up: a full clone can fail
            # purely on space or on one unreachable object.
            shutil.rmtree(destination, ignore_errors=True)
            return self.ensure(name, url, timeout=timeout, allow_full=False)
        if result.returncode != 0:
            shutil.rmtree(destination, ignore_errors=True)
            return None
        return destination

    @staticmethod
    def show(repo: Path, rev: str, path: str) -> str | None:
        return RepoCache.read_blobs(repo, [f"{rev}:{path}"]).get(f"{rev}:{path}")

    @staticmethod
    def read_blobs(repo: Path, specs: list[str]) -> dict[str, str]:
        """Read many ``rev:path`` blobs in a single ``git cat-file --batch``.

        This is the hot path and it is deliberately batched. On a partial clone
        every blob is a network fetch, and the fetch is negotiated once per git
        *process*, so one ``git show`` per blob costs 7.61 s each while one
        batched call costs 0.02 s per blob.

        ``--batch`` output is ``<oid> <type> <size>\\n<payload>\\n`` per object,
        parsed here on bytes because sizes are byte counts and the payloads are
        arbitrary source text that may contain newlines or NULs.
        """
        if not specs:
            return {}
        payload = ("\n".join(specs) + "\n").encode("utf-8")
        # Blobs that are genuinely wanted are fetched; see the class docstring
        # for why this is slow on a partial clone and why full clones are
        # preferred when disk allows.
        env = {**os.environ}
        try:
            result = subprocess.run(
                ["git", "-C", str(repo), "cat-file", "--batch"],
                input=payload, capture_output=True, timeout=900, env=env,
            )
        except subprocess.TimeoutExpired:
            return {}
        out: dict[str, str] = {}
        stream = result.stdout
        position = 0
        for spec in specs:
            newline = stream.find(b"\n", position)
            if newline < 0:
                break
            header = stream[position:newline].decode("utf-8", "replace").split()
            position = newline + 1
            if len(header) < 3:
                # "<spec> missing" -- the object does not exist in this clone.
                continue
            size = int(header[2])
            body = stream[position:position + size]
            position += size + 1  # skip the trailing newline
            if len(body) == size:
                out[spec] = body.decode("utf-8", "replace")
        return out

    @staticmethod
    def changed_python_files(repo: Path, commit: str, limit: int = 12) -> list[str]:
        result = subprocess.run(
            ["git", "-C", str(repo), "show", "--name-only", "--format=", commit],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120,
        )
        if result.returncode != 0:
            return []
        out: list[str] = []
        for line in result.stdout.split("\n"):
            name = line.strip()
            if not name.endswith(".py"):
                continue
            # Test fixtures encode expected-exploit shape, not product behaviour.
            if any(part in name for part in ("/test", "/tests", "test_", "_test.py")):
                continue
            out.append(name)
        return out[:limit]


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

_DEF = re.compile(r"^(\s*)def\s+(\w+)\s*\(", re.M)
_ASYNC_DEF = re.compile(r"^(\s*)async\s+def\s+(\w+)\s*\(", re.M)


def module_context(source: str) -> str:
    """Imports and module-level constants, so the fragment is self-contained."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return ""
    lines = source.split("\n")
    chunks: list[str] = []
    for node in tree.body:
        keep = isinstance(node, (ast.Import, ast.ImportFrom))
        if not keep and isinstance(node, ast.Assign):
            keep = any(
                isinstance(t, ast.Name) and t.id.isupper() for t in node.targets
            )
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None)
        if keep and start and end:
            chunks.append("\n".join(lines[start - 1 : end]))
    return "\n".join(chunks)


def function_bodies(source: str) -> dict[str, str]:
    """Qualified function name -> dedented source, by exact AST span.

    Three defects in the obvious implementation were costing most of the
    corpus, and all three are common in real Python modules:

    * **Name collisions.** Keying by bare name collapses same-named methods of
      different classes, so only the first ``save`` in a module survived. Django
      and Pillow are full of ``save``/``get``/``render`` methods; the one with
      the sink is frequently not the one captured.
    * **Truncation at nested definitions.** Deriving a function's end from the
      *next* function's start line cuts a function in half when it contains a
      nested ``def``, which is how a body can end up as just its ``def`` line.
    * **Nested functions counted as siblings.** ``ast.walk`` returns inner
      definitions interleaved with their enclosing ones.

    Keys are qualified names (``Class.method``, ``outer.inner``) so nothing
    collides, and each span comes from the node's own ``end_lineno``.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return {}
    lines = source.split("\n")
    out: dict[str, str] = {}

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = child.lineno - 1
                if child.decorator_list:
                    start = min(d.lineno for d in child.decorator_list) - 1
                end = getattr(child, "end_lineno", None) or len(lines)
                qualname = f"{prefix}{child.name}"
                text = textwrap_dedent("\n".join(lines[start:end]))
                # A qualified name is unique, but guard anyway so a malformed
                # tree cannot silently drop a function.
                suffix = 1
                key = qualname
                while key in out:
                    suffix += 1
                    key = f"{qualname}#{suffix}"
                out[key] = text
                # Recurse for closures defined inside this function.
                visit(child, f"{qualname}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")

    visit(tree, "")
    return out


def simple_name(qualname: str) -> str:
    """Last segment of a qualified name, for display and record identity."""
    return qualname.rsplit(".", 1)[-1]


def textwrap_dedent(text: str) -> str:
    """Dedent without importing textwrap at module scope for one call site."""
    import textwrap
    return textwrap.dedent(text)


def sink_calls(source: str) -> list[str]:
    """Names of calls that look like sinks, per class, via AST.

    Used only to decide whether a *pre-fix* function plausibly contains the
    vulnerability the advisory names. It is deliberately conservative: a function
    that does not call anything resembling the sink is not accepted as a
    positive, because the label would be unverified.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            names.append(func.attr)
        elif isinstance(func, ast.Name):
            names.append(func.id)
    return names


def matches_class(call_names: list[str], cwe: str) -> bool:
    """Whether any of these bare call names is a sink of this class.

    This is a **name-only** check and is kept only for diagnostics, where the
    import context is not available. It deliberately under-approximates: a bare
    ``load`` is ambiguous, so this returns ``False`` for CWE-502 rather than
    guessing. Use :func:`class_evidence` for any labelling decision.
    """
    category = CWE_TO_CATEGORY.get(cwe)
    if category is None:
        return False
    for name in call_names:
        canonical = canonical_sink(name)
        if canonical is None:
            continue
        spec = SINK_SPECS.get(canonical)
        if spec is not None and spec.category == category:
            return True
    return False


def _call_name(node: ast.AST) -> str:
    """Dotted call name, e.g. ``pickle.loads`` or ``os.path.join``.

    The dotted form matters because the registry resolves bare ``loads`` and
    ``loads`` differently depending on what it was imported from.
    """
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _bindings_from(tree: ast.Module) -> Bindings:
    """Import bindings for the module, from SYRTH's own resolver.

    This is what makes a bare ``load`` mean ``pickle.load`` after
    ``from pickle import load``, and *not* a deserialiser after
    ``import numpy``. Without it the builder labelled every ``load`` call as
    CWE-502, including keras's ``numpy.load`` dataset helpers.
    """
    bindings = Bindings()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings.bind_import(alias.name, alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                bindings.bind_import(
                    node.module, alias.asname or alias.name
                )
    return bindings


def class_evidence(source: str, cwe: str) -> tuple[bool, str]:
    """Does the source call a sink of this class with a non-constant argument?

    Sink resolution is delegated to ``syrth.registry`` so the corpus and the
    analyser cannot drift apart, and argument significance comes from the
    registry's own sink schema rather than a local guess.

    Returns ``(present, call_name)``.
    """
    category = CWE_TO_CATEGORY.get(cwe)
    if category is None:
        return (False, "")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return (False, "")
    bindings = _bindings_from(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if not name:
            continue
        canonical = canonical_sink(name, bindings)
        if canonical is not None:
            spec = SINK_SPECS.get(canonical)
            if spec is not None and spec.category == category:
                if _has_dangerous_argument(node, spec):
                    return (True, name)
                continue
        # An amplifier is also evidence. ``mark_safe`` does not remove taint, it
        # asserts safety, which turns whatever it is given into a confirmed
        # markup sink. A function whose only XSS evidence is ``mark_safe`` is
        # still a genuine CWE-79 record -- django's admin widgets are exactly
        # that shape -- so the argument must not be required here.
        amplifier = amplifier_for(name, bindings)
        if amplifier is not None and category in amplifier.produces:
            return (True, name)
    return (False, "")


def _has_dangerous_argument(node: ast.Call, spec: SinkSpec) -> bool:
    """Whether this call passes a value where the sink's schema says it matters.

    ``cursor.execute("SELECT 1")`` is not an injection and
    ``pickle.loads(b"")`` is not a deserialisation finding, because the argument
    is a constant. The positions that matter come from the registry's own schema,
    so ``execute(sql, params)`` treats the query as dangerous and ignores the
    structurally-safe parameter list.

    A sink with no modelled schema (``danger_positions is None``) treats every
    argument as dangerous. That is the conservative direction for a labelling
    decision: it can admit a record that a human then reviews, never silently
    drop a real finding.
    """
    for index, argument in enumerate(node.args):
        if spec.is_dangerous_position(index) and not isinstance(argument, ast.Constant):
            return True
    for keyword in node.keywords:
        if (spec.is_dangerous_keyword(keyword.arg)
                and not isinstance(keyword.value, ast.Constant)):
            return True
    return False


def module_proximity_sink(
    module_source: str, function_source: str, cwe: str
) -> str:
    """The module-level sink this function produces a value for, or ``""``.

    Returns the qualified sink name rather than a bare boolean so the record can
    name what it relied on. A module-proximity label is not checkable from the
    record alone -- the record is the function plus its imports, not the whole
    file -- so without this field the claim would be unverifiable except by
    trusting the builder. The record already carries repo, commit and file, so
    naming the sink makes the claim checkable against upstream.
    """
    category = CWE_TO_CATEGORY.get(cwe)
    if category is None:
        return ""
    if not _produces_value(function_source):
        return ""
    try:
        tree = ast.parse(module_source)
    except (SyntaxError, ValueError):
        return ""
    bindings = _bindings_from(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if not name:
            continue
        canonical = canonical_sink(name, bindings)
        if canonical is None:
            continue
        spec = SINK_SPECS.get(canonical)
        if spec is not None and spec.category == category:
            return name
    return ""


def module_proximity_evidence(
    module_source: str, function_source: str, cwe: str
) -> bool:
    """Boolean form of :func:`module_proximity_sink`.

    Some vulnerability fixes cannot be labelled at function granularity at all.
    Django's SQL injection fixes are the clear case: ``PostGISOperator.as_sql``
    *constructs* the query string and returns ``(sql, params)``, and a compiler
    elsewhere calls ``cursor.execute(sql, params)``. The function the patch
    touches therefore never calls ``execute``, and the per-function rule
    correctly rejects it -- while the advisory is plainly a real CWE-89.

    Rejecting these is right; **silently accepting them would be wrong too**,
    because a same-module ``execute`` proves only that the module contains a
    sink, not that this function reaches it. So this is recorded as a separate,
    explicitly weaker tier rather than being folded into the direct one.

    The "produces a value" half is deliberately syntactic -- a ``return`` of a
    non-constant, or an assignment of one -- so it stays independent of the
    analyser's own propagation engine.
    """
    return bool(module_proximity_sink(module_source, function_source, cwe))


def _produces_value(function_source: str) -> bool:
    """Whether the function returns or assigns a value that is not a constant."""
    try:
        tree = ast.parse(function_source)
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            if not isinstance(node.value, ast.Constant):
                return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) for t in targets):
                return True
    return False


def candidate_functions(
    before: str, after: str, cwe: str, context: str = ""
) -> tuple[dict[str, str], dict[str, str], list[str], str, dict[str, str], dict[str, str]]:
    """Pair up functions, keeping only those the patch actually changed.

    ``context`` is the module preamble (imports and constants). When given, the
    evidence decision is made on **the record as it will be shipped**, not on the
    bare function body.

    That distinction is not cosmetic. ``paramiko``'s ``SSHConfig._tokenize`` calls
    a bare ``sha1``; judged on the body alone that resolves to nothing and the
    function looks like it has no CWE-327 sink, but the shipped record carries
    ``from cryptography... import SHA1 as sha1`` and the call *does* resolve.
    Deciding on the body filed a direct-sink record as module-proximity. The
    artefact is what a consumer reads, so it is what must be judged.

    Returns ``(changed_before, changed_after, rejected, evidence_call,
    tier_of, module_sink_of)``.

    ``tier_of`` is **per function**, not per file. One file can yield both a
    function that calls the sink itself and one that only produces a value for a
    sink elsewhere; filing the whole file by whichever was seen first mislabels
    whichever came second.
    """
    before_fns = function_bodies(before)
    after_fns = function_bodies(after)
    changed_before: dict[str, str] = {}
    changed_after: dict[str, str] = {}
    tier_of: dict[str, str] = {}
    module_sink_of: dict[str, str] = {}
    rejected: list[str] = []

    def evidence_source(body: str) -> str:
        if not context:
            return body
        return build_record_source(context, body) or body

    for name, body in before_fns.items():
        if name not in after_fns:
            rejected.append(f"{name}:absent-after")
            continue
        if after_fns[name] == body:
            rejected.append(f"{name}:unchanged")
            continue
        present, _call = class_evidence(evidence_source(body), cwe)
        if present:
            changed_before[name] = body
            changed_after[name] = after_fns[name]
            tier_of[name] = "direct-sink"
            continue
        # Second chance at module granularity, recorded as its own tier.
        nearby = module_proximity_sink(before, evidence_source(body), cwe)
        if nearby:
            changed_before[name] = body
            changed_after[name] = after_fns[name]
            tier_of[name] = "module-proximity"
            module_sink_of[name] = nearby
            continue
        rejected.append(f"{name}:no-{cwe}-sink")

    evidence = ""
    for body in changed_before.values():
        _present, call = class_evidence(evidence_source(body), cwe)
        if call:
            evidence = call
            break
    return changed_before, changed_after, rejected, evidence, tier_of, module_sink_of


def _fingerprint(source: str) -> str:
    """Stable hash of a normalised function body, for content deduplication.

    Whitespace and comments are stripped so that a reformat does not read as a
    different vulnerability, while any change to the executable statements does.
    """
    import hashlib

    lines = []
    for line in source.split("\n"):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    normalised = "\n".join(lines)
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def build_record_source(context: str, body: str) -> str | None:
    """Compose a self-contained, parseable snippet, or None."""
    lines = context.split("\n") if context else []
    composed = ("\n".join(lines) + "\n" + textwrap_dedent(body)).strip()
    if not composed:
        return None
    try:
        ast.parse(composed)
    except (SyntaxError, ValueError):
        return None
    return composed


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


def collect_advisories(
    fetcher: Fetcher,
    distributions: list[str],
    packages: list[str],
    pages_per_package: int,
    global_pages: int,
    ecosystem: str,
    cache_path: Path | None,
    refresh: bool,
    workers: int = 8,
) -> tuple[list[Advisory], int]:
    """GHSA per package, plus OSV, merged. Cached to disk.

    Collection is ~26 minutes of API calls serially for the wide package list,
    which made every iteration over extraction, labelling or deduplication pay
    that cost again. The cache holds the merged advisory set keyed by the inputs
    that affect it, so changing the extraction logic costs seconds instead, and
    the fan-out brings the first run down to a few minutes.
    """
    key = {
        "distributions": distributions,
        "packages": packages,
        "pages_per_package": pages_per_package,
        "global_pages": global_pages,
        "ecosystem": ecosystem,
    }
    if cache_path and cache_path.exists() and not refresh:
        try:
            stored = json.loads(cache_path.read_text(encoding="utf-8"))
            if stored.get("key") == key:
                advisories = [
                    Advisory(
                        advisory_id=a["advisory_id"],
                        source=a["source"],
                        cwes=tuple(a["cwes"]),
                        summary=a["summary"],
                        repo_hint=a["repo_hint"],
                        fix_commits=tuple(a["fix_commits"]),
                        package=a["package"],
                    )
                    for a in stored["advisories"]
                ]
                print(f"      reusing {len(advisories)} cached advisories from "
                      f"{cache_path}", flush=True)
                return advisories, sum(1 for a in advisories if a.source == "ghsa")
        except (json.JSONDecodeError, KeyError, TypeError):
            print("      advisory cache unreadable, refetching", flush=True)

    advisories = ghsa_advisories_for_packages(
        fetcher, distributions, pages_per_package, "pip", workers
    )
    ghsa_count = len(advisories)
    if global_pages:
        advisories.extend(ghsa_advisories(fetcher, global_pages, ecosystem))
    ghsa_index = {a.advisory_id: a for a in advisories}
    advisories.extend(osv_advisories(fetcher, packages, workers))

    merged: list[Advisory] = []
    for advisory in advisories:
        twin = ghsa_index.get(advisory.advisory_id)
        if twin is None:
            merged.append(advisory)
            continue
        merged.append(Advisory(
            advisory_id=advisory.advisory_id,
            source=advisory.source if advisory.fix_commits else twin.source,
            cwes=advisory.cwes or twin.cwes,
            summary=advisory.summary or twin.summary,
            repo_hint=twin.repo_hint or advisory.repo_hint,
            fix_commits=tuple(dict.fromkeys(
                twin.fix_commits + advisory.fix_commits
            )),
            package=advisory.package or twin.package,
        ))

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({
            "key": key,
            "advisories": [asdict(a) | {"cwes": list(a.cwes),
                                        "fix_commits": list(a.fix_commits)}
                            for a in merged],
        }, ensure_ascii=False), encoding="utf-8")
        print(f"      cached {len(merged)} advisories -> {cache_path}", flush=True)
    return merged, ghsa_count


def build(args: argparse.Namespace) -> tuple[list[Record], BuildStats]:
    stats = BuildStats(started=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    token = os.environ.get("GITHUB_TOKEN") or None
    limit = 5000 if token else 60
    budget = RateBudget(limit=limit)
    fetcher = Fetcher(token=os.environ.get("GITHUB_TOKEN"), budget=budget)
    cache = RepoCache(Path(args.cache))

    # Advisory collection happens **before** cloning. Cloning first meant every
    # repository was fetched even when it turned out to contribute nothing, and
    # on this corpus django alone is 400 MB; with the wider package list that is
    # hours of cloning spent on empty directories. Repositories are now cloned
    # lazily, once an advisory has been attributed to one.
    distributions = [
        args.distributions.get(name, name) for name, _url in args.repos
    ]
    print(f"[1/5] fetching advisories from GHSA per package "
          f"({len(distributions)} packages x {args.ghsa_pages_per_package} pages, "
          f"budget {budget.limit}/h)", flush=True)
    advisories, ghsa_count = collect_advisories(
        fetcher, distributions, args.packages, args.ghsa_pages_per_package,
        args.ghsa_pages, args.ecosystem,
        Path(args.advisory_cache) if args.advisory_cache else None,
        args.refresh_advisories, args.workers,
    )


    # Merging already happened inside collect_advisories.
    stats.advisories_seen = len(advisories)
    advisories = [a for a in advisories if a.in_scope()]
    stats.advisories_in_scope = len(advisories)
    print(f"      {len(advisories)} advisories in scope "
          f"({ghsa_count} from GHSA)", flush=True)

    # Union by (advisory, commit). First source wins for provenance.
    seen: set[tuple[str, str]] = set()
    unique: list[Advisory] = []
    for advisory in advisories:
        for commit in advisory.fix_commits:
            key = (advisory.advisory_id, commit)
            if key in seen:
                continue
            seen.add(key)
            unique.append(advisory)
            break
    print(f"      {len(unique)} advisories carry a fix commit", flush=True)

    print("[3/5] selecting repositories by advisory density", flush=True)
    candidates = _candidate_repos(unique, args.repos)
    urls = dict(args.repos)
    sizes = repo_sizes(fetcher, candidates, args.repos)
    hits: dict[str, int] = {}
    for advisory in unique:
        hint = advisory.repo_hint.rsplit("/", 1)[-1].lower().removesuffix(".git")
        package = advisory.package.lower()
        for name in candidates:
            low = name.lower()
            if hint == low or package in (low, low.replace("-", "_")):
                hits[name] = hits.get(name, 0) + 1
                break
    wanted, skipped = select_repos_by_density(
        candidates, hits, sizes, args.max_repos, args.max_repo_mb
    )
    stats.skipped.update(skipped)
    over = [f"{n}({sizes.get(n)}MB)" for n in candidates
            if sizes.get(n) is not None and sizes[n] > args.max_repo_mb]
    print(f"      {len(candidates)} candidates, sizes known for {len(sizes)}", flush=True)
    if over:
        print(f"      skipped {len(over)} over the {args.max_repo_mb}MB cap: "
              f"{', '.join(over[:10])}", flush=True)
    print(f"      cloning {len(wanted)}, densest per MB first:", flush=True)
    for name in wanted:
        print(f"        {name}: {sizes.get(name)}MB, "
              f"{hits.get(name, 0)} advisories", flush=True)
        allow_full = (
            sizes.get(name, 0) <= args.max_repo_mb
            and cache._free_bytes(cache.root) > sizes.get(name, 0) * 1024 * 1024 * 2
        )
        if cache.ensure(name, urls[name], allow_full=allow_full):
            stats.repos_cloned += 1
        else:
            stats.skipped[f"{name}:clone-failed"] = "git clone failed"

    print(f"[4/5] extracting functions "
          f"(max {args.max_files} files/commit, {args.max_functions} fn/advisory)",
          flush=True)


    records: list[Record] = []
    record_keys: set[tuple] = set()
    # Records are appended to the output file as they are accepted. A full build
    # is a twenty-minute job over forty repositories, and it was killed twice
    # mid-extraction with nothing on disk; a checkpoint means a killed run still
    # yields everything it finished, and the manifest records how far it got.
    checkpoint = args.checkpoint and args.checkpoint.lower() not in ("0", "none", "")
    if checkpoint:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text("", encoding="utf-8")

    def emit(record: Record) -> None:
        records.append(record)
        if checkpoint:
            with Path(args.out).open("a", encoding="utf-8") as handle:
                handle.write(record.to_json() + "\n")
                handle.flush()
    # A function that is fixed across several commits is the same vulnerability
    # seen more than once. Deduplicate on the function's *content*, not on the
    # commit, so a class fixed by three follow-up commits contributes one record
    # rather than three near-identical ones that would dominate the corpus.
    content_keys: set[tuple] = set()
    classes: set[str] = set()

    by_repo = _group_by_repo(unique, cache.root)
    for repo_name, items in sorted(by_repo.items()):
        repo_path = cache.root / repo_name
        if not (repo_path / ".git").is_dir():
            stats.skipped[f"{repo_name}:not-cloned"] = "clone failed"
            continue
        print(f"      {repo_name}: {len(items)} advisories", flush=True)
        repo_started = time.monotonic()
        for advisory in items[: args.max_advisories_per_repo]:
            # Fix commits are listed newest-first and the first one that lands is
            # almost always the fix itself. Continuing into the remaining commits
            # multiplies blob fetches to re-derive a vulnerability already
            # captured, so an advisory stops once it has produced a record.
            for commit in advisory.fix_commits[: args.max_commits_per_advisory]:
                found_here = 0
                stats.commits_inspected += 1
                try:
                    paths = RepoCache.changed_python_files(
                        repo_path, commit, args.max_files
                    )
                except subprocess.TimeoutExpired:
                    stats.skipped[f"{advisory.advisory_id}:timeout"] = "git timeout"
                    continue
                # Both revisions of every candidate file in one batched read.
                specs = [f"{commit}:{p}" for p in paths]
                specs += [f"{commit}^:{p}" for p in paths]
                blobs = RepoCache.read_blobs(repo_path, specs)
                for path in paths:
                    before = blobs.get(f"{commit}^:{path}")
                    after = blobs.get(f"{commit}:{path}")
                    if not before or not after:
                        continue
                    before_ctx = module_context(before)
                    after_ctx = module_context(after)
                    for cwe in advisory.in_scope():
                        stats.candidates += 1
                        changed_before, changed_after, rejected, evidence, tier_of, module_sink_of = (
                            candidate_functions(before, after, cwe, before_ctx)
                        )
                        if not changed_before:
                            for reason in rejected[:4]:
                                if "no-" in reason and cwe in reason:
                                    stats.rejected_no_sink += 1
                                elif "unchanged" in reason:
                                    stats.rejected_no_change += 1
                            continue
                        for name, body in changed_before.items():
                            if len(changed_before) > args.max_functions:
                                break
                            positive = build_record_source(before_ctx, body)
                            negative = build_record_source(
                                after_ctx, changed_after[name]
                            )
                            if not positive or not negative:
                                stats.rejected_unparseable += 1
                                continue
                            group = advisory.advisory_id
                            pair_id = ":".join(
                                (advisory.advisory_id, commit, path, name, cwe)
                            )
                            key = (repo_name, commit, path, name, cwe)
                            if key in record_keys:
                                continue
                            # Same function body, same class: the same
                            # vulnerability reached by a different commit.
                            # Scoped per repo and file, deliberately not per
                            # advisory: keras carries two advisories on one
                            # commit, and those are different findings.
                            content_key = (
                                repo_name, path, name, cwe,
                                _fingerprint(positive),
                            )
                            if content_key in content_keys:
                                stats.deduplicated += 1
                                continue
                            record_keys.add(key)
                            content_keys.add(content_key)
                            _present, call = class_evidence(positive, cwe)
                            emit(Record(
                                pair_id=pair_id,
                                group=group,
                                source=positive,
                                label=cwe,
                                cwe=cwe,
                                repo=repo_name,
                                advisory_id=advisory.advisory_id,
                                commit=commit,
                                file=path,
                                function=simple_name(name),
                                qualname=name,
                                kind="vulnerable",
                                origin_source=advisory.source,
                                sink_call=call or evidence,
                                evidence=tier_of.get(name, "direct-sink"),
                                module_sink=module_sink_of.get(name, ""),
                            ))
                            emit(Record(
                                pair_id=pair_id,
                                group=group,
                                source=negative,
                                label="",
                                cwe="",
                                repo=repo_name,
                                advisory_id=advisory.advisory_id,
                                commit=commit,
                                file=path,
                                function=simple_name(name),
                                qualname=name,
                                kind="patched",
                                origin_source=advisory.source,
                                sink_call=call or evidence,
                                evidence=tier_of.get(name, "direct-sink"),
                                module_sink=module_sink_of.get(name, ""),
                            ))
                            stats.accepted_positive += 1
                            stats.accepted_negative += 1
                            found_here += 1
                            classes.add(cwe)
                            tier = tier_of.get(name, "")
                            if tier:
                                stats.evidence_tiers[tier] = (
                                    stats.evidence_tiers.get(tier, 0) + 1
                                )
                            stats.repos_covered[repo_name] = (
                                stats.repos_covered.get(repo_name, 0) + 1
                            )
                if found_here:
                    break
                if (args.repo_budget_seconds
                        and time.monotonic() - repo_started
                        > args.repo_budget_seconds):
                    # A partial clone fetches blobs over the network at roughly
                    # 6.5 s each, so one large repository can otherwise consume
                    # the entire run. Stop here and say so, rather than letting
                    # the absence of records look like absence of findings.
                    stats.skipped[f"{repo_name}:time-budget"] = (
                        f"stopped after {args.repo_budget_seconds}s"
                    )
                    print(f"      {repo_name}: time budget reached, moving on",
                          flush=True)
                    break

    stats.classes_covered = sorted(classes)
    stats.rate = budget.snapshot()
    stats.errors = fetcher.errors[:40]
    print("[5/5] writing", flush=True)
    return records, stats


def _candidate_repos(
    advisories: list[Advisory], repos: list[tuple[str, str]]
) -> list[str]:
    """Which listed repositories could plausibly own these fix commits.

    Attribution happens before cloning, on names alone, because the exact
    signal — does this commit exist in this clone — needs the clone. Matching on
    the advisory's repository hint, its package name, and the clone name covers
    enough to decide what is worth fetching; ``_group_by_repo`` then confirms
    with commit presence once the clone exists.
    """
    names = {name.lower(): name for name, _url in repos}
    hits: dict[str, int] = {}
    for advisory in advisories:
        hint = advisory.repo_hint.rsplit("/", 1)[-1].lower().removesuffix(".git")
        package = advisory.package.lower().replace("_", "-")
        for candidate in (hint, package, advisory.package.lower()):
            if candidate in names:
                hits[names[candidate]] = hits.get(names[candidate], 0) + 1
                break
    return sorted(
        hits,
        # Densest advisories first, but monorepos last: they cost the most to
        # clone and would otherwise starve every other repository of the run.
        key=lambda n: -hits[n],
    )


def repo_sizes(
    fetcher: Fetcher, names: list[str], repo_entries: list[tuple[str, str]]
) -> dict[str, int]:
    """Clone size in MB per repository, from the GitHub API.

    Guessing which repositories are expensive was costing the run 15+ minutes
    per clone: ``apache-airflow`` and ``mlflow`` each blocked every other
    repository behind them, and both would have been skipped by a size cap. The
    API reports ``size`` in KB for one request each, which is far cheaper than
    discovering it by cloning.
    """
    out: dict[str, int] = {}
    urls = dict(repo_entries)
    for name in names:
        url = urls.get(name, "")
        slug = url.rsplit("github.com/", 1)[-1].removesuffix(".git") if url else ""
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", slug):
            continue
        payload = fetcher.get(f"{GITHUB_API}/repos/{slug}", budgeted=False)
        if isinstance(payload, dict) and isinstance(payload.get("size"), int):
            out[name] = payload["size"] // 1024
    return out


def select_repos_by_density(
    names: list[str],
    hits: dict[str, int],
    sizes: dict[str, int],
    limit: int,
    max_mb: int,
) -> tuple[list[str], dict[str, str]]:
    """Pick repositories by advisories per megabyte, dropping oversized ones.

    Returns ``(chosen, skipped)``. Ordering by raw advisory count sends the run
    straight at the largest projects; ordering by advisories per megabyte gets
    the most labelled material per minute of cloning instead.
    """
    chosen: list[str] = []
    skipped: dict[str, str] = {}
    scored: list[tuple[float, str]] = []
    for name in names:
        size = sizes.get(name)
        if size is None:
            skipped[f"{name}:no-size"] = "size lookup failed"
            continue
        if size > max_mb:
            skipped[f"{name}:{size}MB"] = f"over {max_mb}MB cap"
            continue
        density = hits[name] / max(size, 1) ** 0.5
        scored.append((density, name))
    scored.sort(reverse=True)
    chosen = [name for _d, name in scored[:limit]]
    return chosen, skipped


def _group_by_repo(advisories: list[Advisory], cache_root: Path) -> dict[str, list[Advisory]]:
    """Attach each advisory to a locally cloned repository.

    Matching is done on three signals, in order of reliability:

    1. **The fix commit exists in the clone.** ``git cat-file -e`` is exact and
       costs one fast local call, so a renamed or derived repository name cannot
       cause a miss.
    2. The advisory's repository hint contains the clone's name.
    3. The package name equals the clone's name.

    Signal 1 is what makes this reliable. GHSA reports the repository that
    *published* the advisory, which is frequently not the repository the fix
    landed in, and name-based matching alone discarded most advisories.
    """
    grouped: dict[str, list[Advisory]] = {}
    clones = [p for p in (cache_root.iterdir() if cache_root.exists() else [])
              if (p / ".git").is_dir()]
    if not clones:
        return grouped

    # Confirm attribution in **one git process per clone**, not one per
    # (advisory, commit) pair. The naive loop spawned ~35,000 `git cat-file -e`
    # calls for 338 advisories across 35 clones and burned over 20 minutes before
    # printing a single line; `--batch-check` answers every candidate in a single
    # pipe and takes the same work to about a second.
    present_by_clone = {
        repo_path.name: _present_commits(repo_path, _all_commits(advisories))
        for repo_path in clones
    }

    for advisory in advisories:
        for repo_path in clones:
            if present_by_clone[repo_path.name] & set(advisory.fix_commits[:3]):
                grouped.setdefault(repo_path.name, []).append(advisory)
                break
        else:
            name = advisory.repo_hint.rsplit("/", 1)[-1].lower()
            package = advisory.package.lower()
            for repo_path in clones:
                if name == repo_path.name.lower() or package == repo_path.name.lower():
                    grouped.setdefault(repo_path.name, []).append(advisory)
                    break
    return grouped


def _all_commits(advisories: list[Advisory]) -> list[str]:
    """Every candidate commit across advisories, deduplicated, order kept."""
    seen: dict[str, None] = {}
    for advisory in advisories:
        for commit in advisory.fix_commits[:3]:
            seen.setdefault(commit, None)
    return list(seen)


def _is_partial_clone(repo_path: Path) -> bool:
    """Whether this clone filters blobs.

    Such a clone must never be asked about objects it may not hold: git tries to
    resolve them over the network, and asking it about 400 absent commits on
    ``ansible`` hung for over 11 minutes on git 2.44 even with
    ``GIT_NO_LAZY_FETCH=1`` set. Attribution is therefore restricted to fully
    cloned repositories, where a missing object answers immediately (0.07 s for
    a batch of three on this machine).
    """
    result = subprocess.run(
        ["git", "-C", str(repo_path), "config", "--get",
         "remote.origin.partialclonefilter"],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def _present_commits(repo_path: Path, commits: list[str]) -> set[str]:
    """Which of ``commits`` exist in this clone, via one batched check.

    Results are keyed by the object id git echoes back rather than matched by
    position. ``cat-file --batch-check`` does **not** emit exactly one line per
    request: a missing object can produce a trailing extra ``missing`` record, so
    positional zipping silently mis-assigns every commit after the first gap.
    """
    if not commits or _is_partial_clone(repo_path):
        return set()
    payload = ("\n".join(commits) + "\n").encode("utf-8")
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "--batch-check"],
            input=payload, capture_output=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        return set()
    status: dict[str, bool] = {}
    for line in result.stdout.decode("utf-8", "replace").split("\n"):
        parts = line.split()
        if len(parts) >= 2 and parts[0] != "":
            status[parts[0]] = "missing" not in parts[-1]
    present: set[str] = set()
    for commit in commits:
        for form in (commit, commit.lower()):
            if form in status and status[form]:
                present.add(commit)
                break
    return present


def _commit_present(repo_path: Path, commits: tuple[str, ...]) -> bool:
    """Whether any of ``commits`` exists in this clone."""
    for commit in commits[:3]:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", f"{commit}^{{commit}}"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return True
    return False


def write_jsonl(records: list[Record], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(record.to_json() + "\n")


def write_manifest(stats: BuildStats, path: Path) -> None:
    payload = asdict(stats)
    payload["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="data/corpus.jsonl")
    parser.add_argument("--manifest", default="data/corpus_manifest.json")
    parser.add_argument("--cache", default="experiments/scratch/repos")
    parser.add_argument("--ghsa-pages", type=int, default=12,
                        help="GHSA pages of 100 (budget permitting)")
    parser.add_argument("--ecosystem", default="PyPI")
    parser.add_argument("--max-files", type=int, default=12)
    parser.add_argument("--max-functions", type=int, default=6)
    parser.add_argument("--max-commits-per-advisory", type=int, default=1)
    parser.add_argument("--max-advisories-per-repo", type=int, default=400,
                        help="cap per repo so one large history cannot starve "
                             "the others or overrun the run")
    parser.add_argument("--packages", nargs="*", default=[
        d for _n, _u, d in DEFAULT_REPOS
    ], help="PyPI distributions for the OSV pass; defaults to the repo table")
    parser.add_argument("--distributions", type=lambda s: dict(
        p.split("=", 1) for p in s.split(",") if p
    ), default={name: dist for name, _url, dist in DEFAULT_REPOS},
        help="clone-name=PyPI-distribution overrides, comma separated")
    parser.add_argument("--repos", nargs="*", default=[
        f"{name}={url}" for name, url, _ in DEFAULT_REPOS
    ])
    parser.add_argument("--ghsa-pages-per-package", type=int, default=7,
                        help="pages of 100 per affected package. The per-package "
                             "query is the primary GHSA path; --ghsa-pages only "
                             "applies to the optional global sweep.")
    parser.add_argument("--max-repo-mb", type=int, default=300,
                        help="skip repositories whose full clone exceeds this. "
                             "Sized from the GitHub API, not discovered by "
                             "waiting on a clone that never finishes.")
    parser.add_argument("--max-repos", type=int, default=40,
                        help="cap on cloned repositories, densest per MB first")
    parser.add_argument("--checkpoint", default="on",
                        help="'on' writes each accepted record to --out as it is "
                             "produced, so a killed run still yields what it "
                             "finished. 'off' buffers and writes once at the end.")
    parser.add_argument("--repo-budget-seconds", type=int, default=420,
                        help="stop extracting from one repository after this "
                             "long. A partial clone fetches blobs over the "
                             "network, so a single large repository can "
                             "otherwise stall the whole run.")
    parser.add_argument("--workers", type=int, default=8,
                        help="concurrent API requests during collection. "
                             "Collection is latency-bound, not CPU-bound: 192 "
                             "distributions take ~26 min serially and ~3 min here")
    parser.add_argument("--advisory-cache",
                        default="experiments/scratch/advisories.json",
                        help="reuse and store collected advisories here; "
                             "collection is ~26 min of API calls")
    parser.add_argument("--refresh-advisories", action="store_true",
                        help="ignore the advisory cache and refetch")
    parser.add_argument("--limit-records", type=int, default=0,
                        help="stop after N accepted positives (0 = no limit)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.repos = [tuple(r.split("=", 1)) for r in args.repos]

    records, stats = build(args)
    if args.limit_records:
        positives = sum(1 for r in records if r.label)
        if positives > args.limit_records:
            groups: dict[str, list[Record]] = {}
            for record in records:
                if record.label:
                    groups.setdefault(record.group, []).append(record)
            kept: list[Record] = []
            for group in list(groups)[: args.limit_records]:
                kept.extend(groups[group])
            records = kept

    # The checkpoint file already holds every record in order, but only when no
    # limit trimmed the set afterwards; rewriting unconditionally keeps the output
    # equal to what this run actually decided.
    write_jsonl(records, Path(args.out))
    write_manifest(stats, Path(args.manifest))

    print()
    print("=" * 66)
    print("corpus summary")
    print("=" * 66)
    print(f"repos cloned          : {stats.repos_cloned}")
    print(f"advisories seen       : {stats.advisories_seen}")
    print(f"  in scope            : {stats.advisories_in_scope}")
    print(f"commits inspected     : {stats.commits_inspected}")
    print(f"candidates evaluated  : {stats.candidates}")
    print(f"records written       : {len(records)}")
    print(f"  vulnerable          : {sum(1 for r in records if r.label)}")
    print(f"  patched             : {sum(1 for r in records if not r.label)}")
    print(f"rejected: no sink     : {stats.rejected_no_sink}")
    print(f"rejected: unchanged   : {stats.rejected_no_change}")
    print(f"rejected: unparseable : {stats.rejected_unparseable}")
    print(f"deduplicated (same function, later commit): {stats.deduplicated}")
    print(f"evidence tiers          : {stats.evidence_tiers}")
    print(f"classes covered       : {stats.classes_covered}")
    print(f"rate budget           : {stats.rate}")
    if stats.skipped:
        print("skipped:")
        for key, why in list(stats.skipped.items())[:8]:
            print(f"  {key}: {why}")
    print(f"-> {args.out}")
    print(f"-> {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
