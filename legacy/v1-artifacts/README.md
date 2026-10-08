# v1 artefacts: deliberately empty

The withdrawn pipeline left five trained model bundles, three training datasets
and a generated C engine on disk -- about 100 MB in total. They were moved here
first, and that was the wrong call. They are removed instead.

The withdrawal audit in `../../paper/WITHDRAWN.md` works by describing defects in
code: a meta-learner that read a bundle key that did not exist, a 20-element
feature vector passed to a model expecting 53, a constant probability swap against
a hard-coded RCE index, and ground-truth CWE text injected as a training feature.
None of those is checkable by opening a pickle or a JSON dataset. Keeping 48 MB of
weights in the repository would have implied the audit could be re-verified
against them, which it cannot.

What remains from v1 is the part that is actually checkable and readable: the
scripts under `../v1-scripts/` and `../../experiments/v1/`, and the corpus builder
in `../../tools/build_corpus.py`, which replaced the dataset pipeline.

To re-run anything from that era you need to rebuild its inputs from the advisories
it consumed. The corpora were never a source of truth here either: they are
regenerated rather than versioned, for the same reason.