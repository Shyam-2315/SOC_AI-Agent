from pydantic import BaseModel, ConfigDict, field_validator


def _sanitize_string(value: str) -> str:
    return "".join(
        character
        for character in value
        if character == "\n" or character == "\t" or ord(character) >= 32
    )


class APIModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    @field_validator("*", mode="before")
    @classmethod
    def sanitize_strings(cls, value):
        if isinstance(value, str):
            return _sanitize_string(value).strip()
        return value
