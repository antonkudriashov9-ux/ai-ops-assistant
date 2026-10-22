from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Action = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


class IncidentAnalysisSchema(BaseModel):
    """Validate structure and bounds; technical correctness still needs human review."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=120, description="Краткий заголовок инцидента")
    severity: Literal["low", "medium", "high", "critical"]
    affected_service: Literal["linux_os", "postgresql", "docker", "network", "app"]
    summary: str = Field(min_length=1, max_length=2000, description="Факты, гипотезы и ограничения анализа")
    recommended_actions: list[Action] = Field(min_length=1, max_length=6)
