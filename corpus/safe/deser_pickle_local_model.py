"""Loads a model file shipped with the application, not user input."""
import pickle
from pathlib import Path

MODEL_PATH = Path(__file__).with_name("model.pkl")


def load_model():
    with open(MODEL_PATH, "rb") as fh:
        return pickle.load(fh)
