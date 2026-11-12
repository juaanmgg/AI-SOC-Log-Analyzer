from unittest.mock import MagicMock, patch

from ai_soc.adapters.llm import SYSTEM_PROMPT, GroqThreatDetector
from ai_soc.domain.models import SeverityEnum, ThreatItem, ThreatReport


def test_groq_detector_uses_pydantic_structured_output() -> None:
    expected = ThreatReport(
        amenazas=[ThreatItem(ip="8.8.8.8", tipo="Scanner", severidad=SeverityEnum.MEDIA)]
    )
    fake_chain = MagicMock()
    fake_chain.invoke.return_value = expected
    fake_client = MagicMock()
    fake_client.with_structured_output.return_value = fake_chain

    with patch("ai_soc.adapters.llm.ChatGroq", return_value=fake_client) as groq:
        detector = GroqThreatDetector("test-key", model="test-model", timeout=3)
        result = detector.analyze('<untrusted_evidence ip="8.8.8.8">data</untrusted_evidence>')

    groq.assert_called_once_with(
        model="test-model",
        groq_api_key="test-key",
        timeout=3,
        temperature=0,
    )
    fake_client.with_structured_output.assert_called_once_with(ThreatReport)
    assert result == expected
    assert SYSTEM_PROMPT in fake_chain.invoke.call_args.args[0][0][1]
