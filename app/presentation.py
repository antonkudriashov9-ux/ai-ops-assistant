from html import escape

from app.schemas import IncidentAnalysisSchema


def _escaped_parts(text: str, limit: int = 3000) -> list[str]:
    parts, current, size = [], [], 0
    for character in text:
        escaped = escape(character)
        units = len(escaped.encode("utf-16-le")) // 2
        if size + units > limit:
            parts.append("".join(current))
            current, size = [], 0
        current.append(escaped)
        size += units
    if current:
        parts.append("".join(current))
    return parts


def render_analysis(analysis: IncidentAnalysisSchema, source: str = "llm") -> list[str]:
    severity = {"critical": "🔴 Критический", "high": "🟠 Высокий", "medium": "Средний", "low": "Низкий"}
    modes = {
        "llm": "LLM · формат проверен",
        "heuristic": "Эвристика · локальные правила, без LLM",
        "demo": "Демонстрация · учебный пример, без LLM",
    }
    blocks = [
        f"<b>{escape(analysis.title)}</b>\n"
        f"{severity[analysis.severity]} · <code>{analysis.affected_service}</code>\n"
        f"<i>{modes.get(source, modes['llm'])}</i>"
    ]
    for index, part in enumerate(_escaped_parts(analysis.summary)):
        blocks.append(("<b>Что произошло</b>\n" if index == 0 else "") + part)
    blocks.append("<b>Следующие шаги</b>")
    for index, action in enumerate(analysis.recommended_actions, 1):
        for part_index, part in enumerate(_escaped_parts(action)):
            blocks.append((f"<b>{index}.</b> " if part_index == 0 else "↳ ") + part)
    blocks.append(
        "<i>Это предварительный разбор. Проверьте гипотезы и команды перед выполнением. "
        "Бот не выполняет команды на серверах.</i>"
    )
    chunks, current = [], ""
    for block in blocks:
        candidate = current + ("\n\n" if current else "") + block
        if len(candidate.encode("utf-16-le")) // 2 > 3900:
            chunks.append(current)
            current = block
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks
