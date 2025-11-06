import json
from typing import Any


class SkyvernJSONLogEncoder(json.JSONEncoder):
    """Custom JSON encoder for Skyvern logs that handles non-serializable objects"""

    def default(self, obj: Any) -> Any:
        # Use local var for speed, reduce function calls
        _encode_value = self._encode_value

        # Check special serialization methods in (most likely) order
        if hasattr(obj, "model_dump"):
            return _encode_value(obj.model_dump())


        if hasattr(obj, "__dataclass_fields__"):
            fields = obj.__dataclass_fields__
            # Avoid repeated getattr, use dict comprehension directly
            return _encode_value({k: getattr(obj, k) for k in fields})

        # Check if obj has a dict-producing method
        to_dict = getattr(obj, "to_dict", None)
        if callable(to_dict):
            return _encode_value(to_dict())

        asdict = getattr(obj, "asdict", None)
        if callable(asdict):
            return _encode_value(asdict())

        # If obj is a class instance with __dict__
        dct = getattr(obj, "__dict__", None)
        if isinstance(dct, dict):
            # Avoid extra function call, do filtering in generator expression
            attrs = {k: _encode_value(v)
                     for k, v in dct.items()
                     if not k.startswith("_") and not callable(v)}
            return {
                "type": obj.__class__.__name__,
                "attributes": attrs,
            }

        try:
            return str(obj)
        except Exception:
            return f"<non-serializable-{obj.__class__.__name__}>"

    def _encode_value(self, value: Any) -> Any:
        """Helper method to encode nested values recursively"""
        # Fast path for common types
        if type(value) in (str, int, float, bool, type(None)):
            return value

        if isinstance(value, (list, tuple)):
            return [self._encode_value(item) for item in value]

        if isinstance(value, dict):
            return {self._encode_value(k): self._encode_value(v) for k, v in value.items()}

        # For any other type, try to encode it using our custom logic
        return self.default(value)

    @classmethod
    def dumps(cls, obj: Any, **kwargs: Any) -> str:
        """Helper method to properly encode objects to JSON string"""
        return json.dumps(obj, cls=cls, **kwargs)
