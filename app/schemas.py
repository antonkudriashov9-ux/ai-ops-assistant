from typing import List, Literal
from pydantic import BaseModel, Field


class IncidentAnalysisSchema(BaseModel):
    """
    Строгая схема для валидации выхода ИИ-агента.
    Если модель возвращает галлюцинацию или неполные данные,
    валидатор отбрасывает результат.
    """
    title: str = Field(description="Краткий заголовок сбоя или инцидента", max_length=120)
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="Уровень критичности инцидента"
    )
    affected_service: str = Field(
        description="Определенный компонент: linux_os, postgresql, docker, network, app"
    )
    summary: str = Field(description="Понятное объяснение сути сбоя для инженера")
    recommended_actions: List[str] = Field(
        description="Четкий пошаговый список действий по устранению проблемы",
        min_length=1
    )
