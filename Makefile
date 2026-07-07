# SYRTH — production workflow
# Run everything inside WSL (tested on kali-linux). See docs/INSTALLATION.md.
#
#   make setup        # create .venv and install dependencies (CPU torch)
#   make dataset      # (re)build aligned, leak-free train/test datasets
#   make train        # train the model -> syrth_model.joblib + syrth_engine.h
#   make bench        # run the benchmark (incl. dev/fast agreement proof)
#   make scan F=views.py   # scan a file with the trained model

PY       ?= python3
VENV     ?= .venv
DATASET  ?= _balanced_dataset.json
TESTSET  ?= testingMassiveDataset.json
TORCH_CPU_INDEX := https://download.pytorch.org/whl/cpu

.PHONY: setup dataset train bench scan clean

setup:
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install torch --index-url $(TORCH_CPU_INDEX)
	$(VENV)/bin/pip install -r requirements.txt

dataset:
	$(PY) repair_dataset.py _full_dataset.json $(DATASET) $(TESTSET)

train:
	$(VENV)/bin/python train_model.py --dataset $(DATASET)

bench:
	$(VENV)/bin/python benchmark.py --testing-dataset $(TESTSET)

scan:
	$(VENV)/bin/python syrth_scan.py --file $(F) --mode dev

clean:
	rm -f syrth_model.joblib syrth_engine.so syrth_engine.h
	rm -rf $(VENV)
