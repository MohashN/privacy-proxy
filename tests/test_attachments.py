"""Images and PDFs (#10): a PDF's text is read, and neither goes to a provider not Trusted."""

import asyncio
import base64
import io
import json
import time
import uuid

import httpx
import pytest
import yaml
from pypdf import PdfReader, PdfWriter
from test_api_lane import PNR, PROVIDER_KEYS, PROVIDERS_FILE
from test_detection import refusal, send
from test_openai_format import CHAT, KEYS, SMOKE, completion, post
from test_subscription_lane import SCANNER, Upstream

from privacy_proxy import cli, detection
from privacy_proxy.apilane import ApiLane, Keys, Providers, Spend
from privacy_proxy.detection import Detection, Scanner

MESSAGES = "/v1/messages"
# Made up, like everything here: one pixel's worth of base64, never decoded.
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="


def pdf(*pages: str, note: str | None = None, indirect_note: bool = False) -> bytes:
    """A PDF with one line of Helvetica text per page, written by hand.

    ``note`` puts a sticky note holding that text on the first page, outside its text;
    ``indirect_note`` stores that text as an object of its own, referenced by the note.
    """
    count = len(pages)
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(count))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {count} >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for i, text in enumerate(pages):
        stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
        annots = ""
        if note is not None and i == 0:
            contents = f"{4 + 2 * count} 0 R" if indirect_note else f"({note})"
            annots = f" /Annots [<< /Type /Annot /Subtype /Text /Rect [0 0 20 20] /Contents {contents} >>]"
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]{annots} "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {5 + 2 * i} 0 R >>".encode()
        )
        objects.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream))
    if note is not None and indirect_note:
        objects.append(f"({note})".encode())
    return write_pdf(objects)


def write_pdf(objects: list[bytes]) -> bytes:
    """A PDF of these objects, numbered from 1; object 1 is the catalog."""
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def fresh(text: str = "an invoice for the garden shed") -> bytes:
    """A PDF no other test has sent, so the PDF cache can't answer for it."""
    return pdf(f"{text} {uuid.uuid4().hex}")


def document(data: bytes | str) -> dict:
    data = data if isinstance(data, str) else b64(data)
    source = {"type": "base64", "media_type": "application/pdf", "data": data}
    return {"type": "document", "source": source}


def image() -> dict:
    return {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": PNG}}


def file_part(data: bytes) -> dict:
    url = f"data:application/pdf;base64,{b64(data)}"
    return {"type": "file", "file": {"filename": "payslip.pdf", "file_data": url}}


def image_part() -> dict:
    return {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG}"}}


def anthropic_turn(model: str, *blocks: dict) -> bytes:
    content = [*blocks, {"type": "text", "text": "summarise this"}]
    body = {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": content}]}
    return json.dumps(body).encode()


def openai_turn(model: str, *parts: dict) -> bytes:
    content = [{"type": "text", "text": "summarise this"}, *parts]
    body = {
        "model": model,
        "max_completion_tokens": 16,
        "messages": [{"role": "user", "content": content}],
    }
    return json.dumps(body).encode()


def anthropic_headers() -> dict[str, str]:
    return {
        "x-api-key": SMOKE,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
    }


def message_of(response: httpx.Response) -> str:
    assert response.status_code == 400
    return response.json()["error"]["message"]


@pytest.fixture
def lane(tmp_path):
    spend = Spend(tmp_path / "spend.db")
    yield ApiLane(Keys.from_dict(KEYS), Providers.load(PROVIDERS_FILE), spend, PROVIDER_KEYS)
    spend.close()


def ok() -> Upstream:
    return Upstream(
        lambda r: (
            completion()
            if r.url.path.endswith("/chat/completions")
            else httpx.Response(200, json={"type": "message", "content": []})
        )
    )


# --- A PDF's text is read: the personnummer in a payslip is refused ---


async def test_a_pdf_holding_a_personnummer_is_refused_in_the_subscription_lane():
    body = json.loads(anthropic_turn("claude-sonnet-5-5", document(pdf(f"Personnummer {PNR}"))))
    response, upstream = await send(body)

    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []


async def test_a_pdf_holding_a_personnummer_is_refused_in_the_api_lane(lane):
    upstream = ok()
    body = anthropic_turn("claude-haiku-5-5", document(pdf(f"Personnummer {PNR}")))
    response, _ = await post(lane, upstream, body, path=MESSAGES, **anthropic_headers())

    assert message_of(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []


async def test_a_pdf_as_an_openai_file_part_is_refused_too(lane):
    upstream = ok()
    body = openai_turn("gpt-5.6-luna", file_part(pdf(f"Personnummer {PNR}")))
    response, _ = await post(lane, upstream, body)

    assert message_of(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []

    # And without a proxy key, at Anthropic's OpenAI-compatible endpoint.
    response, upstream = await send(json.loads(body), path=CHAT)
    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []


def form_pdf(field: bytes, *extra: bytes) -> bytes:
    """A one-page PDF whose form holds ``field`` (object 5); ``extra`` are objects 6 on."""
    return write_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            b"<< /Fields [5 0 R] >>",
            field,
            *extra,
        ]
    )


def note_pdf(annotation: bytes, *extra: bytes) -> bytes:
    """A one-page PDF with ``annotation`` on its page; ``extra`` are objects 4 on."""
    return write_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [%s] >>" % annotation,
            *extra,
        ]
    )


def stream(data: bytes, entries: bytes = b"") -> bytes:
    return b"<< /Length %d %s >>\nstream\n%s\nendstream" % (len(data), entries, data)


def verdict(data: bytes) -> list[str]:
    body = json.loads(anthropic_turn("claude-sonnet-5-5", document(data)))
    return [d.type for d in Scanner(SCANNER.denylist).check(body, trusted=True)]


NOTE = b"/Type /Annot /Subtype /Widget /Rect [0 0 1 1]"


@pytest.mark.parametrize(
    "data",
    [
        pdf("Page one", note="a note"),
        pdf("Page one", note=f"pnr {PNR}", indirect_note=True),
        form_pdf(b"<< /T (f) /FT /Tx /V (filled in) >>"),
        note_pdf(b"<< %s /AP << /N 4 0 R >> >>" % NOTE, stream(b"BT (x) Tj ET", b"/Subtype /Form")),
        # A link with an appearance of its own, which a viewer draws on the page.
        note_pdf(
            b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /AP << /N 4 0 R >> >>",
            stream(f"BT ({PNR}) Tj ET".encode(), b"/Subtype /Form"),
        ),
        note_pdf(
            b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /JavaScript /JS (x) >> >>"
        ),
        note_pdf(b"<< /Type /Annot /Subtype 4 0 R /Rect [0 0 1 1] >>", b"/FreeText"),
        write_pdf(
            [
                b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /XFA [] >> >>",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            ]
        ),
    ],
    ids=[
        "note",
        "note-apart",
        "form",
        "widget",
        "link-appearance",
        "link-script",
        "subtype-apart",
        "xfa",
    ],
)
def test_a_pdf_with_a_form_or_notes_is_refused_whole(data):
    # Whatever they hold: a form's values and a note's text can be stored, encoded and
    # drawn in more ways than a check can follow, so the PDF is refused, not read.
    assert verdict(data) == ["PDF_NOT_FLAT"]


@pytest.mark.parametrize(
    "data",
    [
        note_pdf(b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI (x) >> >>"),
        # As InDesign writes an in-document link: a page and a structure element.
        note_pdf(
            b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /GoTo /D [3 0 R /Fit] /SD [4 0 R] >> >>",
            b"<< /Type /StructElem /S /P >>",
        ),
        write_pdf(
            [
                b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] >> >>",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            ]
        ),
    ],
    ids=["link", "goto-with-structure", "empty-form"],
)
def test_links_and_an_empty_form_leave_a_pdf_flat(data):
    assert verdict(data) == []


@pytest.mark.parametrize(
    "link",
    [
        f"/Contents (pnr {PNR})".encode(),
        f"/A << /S /URI /URI (https://example.com/?pnr={PNR}) >>".encode(),
    ],
    ids=["description", "address"],
)
def test_a_links_description_and_address_are_checked_as_text(link):
    # Accessible exports describe every link, so a description is read, not refused.
    data = note_pdf(b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] %s >>" % link)
    assert verdict(data) == ["SE_PERSONNUMMER"]
    clean = note_pdf(b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /Contents (Home page) >>")
    assert verdict(clean) == []


async def test_a_pdf_labelled_an_image_is_still_read(lane):
    data = b64(pdf(f"Personnummer {PNR}"))
    source = {"type": "base64", "media_type": "image/png", "data": data}
    body = json.loads(anthropic_turn("claude-sonnet-5-5", {"type": "image", "source": source}))
    response, _ = await send(body)
    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"

    # An OpenAI file part is read whatever it is labelled.
    part = {"type": "file", "file": {"file_data": f"data:image/png;base64,{data}"}}
    upstream = ok()
    response, _ = await post(lane, upstream, openai_turn("gpt-5.6-luna", part))
    assert message_of(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"


async def test_a_data_url_outside_an_image_or_file_part_is_read_as_text(lane):
    # Only inside a media part is a data URL an attachment; elsewhere it is text.
    tool = {
        "type": "function",
        "function": {"name": "f", "url": f"data:image/png;base64,{PNR}", "parameters": {}},
    }
    body = json.loads(openai_turn("gpt-5.6-luna"))
    body["tools"] = [tool]
    upstream = ok()
    response, _ = await post(lane, upstream, json.dumps(body).encode())

    assert message_of(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"


async def test_a_denylisted_name_on_a_later_page_is_refused():
    body = json.loads(
        anthropic_turn("claude-sonnet-5-5", document(pdf("Page one", "Dear Testa Testsson")))
    )
    response, _ = await send(body)

    assert refusal(response) == "privacy-proxy: refused (DENYLIST)"


# --- A clean PDF passes to a Trusted provider, byte for byte ---


async def test_a_clean_pdf_passes_to_anthropic_byte_for_byte(lane):
    body = anthropic_turn("claude-sonnet-5-5", document(fresh()))
    response, upstream = await send(body)
    assert response.status_code == 200
    assert upstream.bodies == [body]

    body = anthropic_turn("claude-haiku-5-5", document(fresh()))
    upstream = ok()
    response, _ = await post(lane, upstream, body, path=MESSAGES, **anthropic_headers())
    assert response.status_code == 200
    assert upstream.bodies == [body]


async def test_a_clean_pdf_passes_to_openai_byte_for_byte(lane):
    body = openai_turn("gpt-5.6-luna", file_part(fresh()))
    upstream = ok()
    response, _ = await post(lane, upstream, body)

    assert response.status_code == 200
    assert upstream.bodies == [body]


# --- A PDF that can't be read, or is over a limit ---


def encrypted() -> bytes:
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(fresh())))
    writer.encrypt("", algorithm="RC4-128")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


@pytest.mark.parametrize(
    "data",
    [
        b64(b"%PDF-1.4\nthis is not a PDF at all"),
        "this is not base64 !!",
        encrypted,
    ],
    ids=["corrupt", "not-base64", "encrypted-even-with-an-empty-password"],
)
async def test_a_pdf_that_cant_be_read_is_refused(data):
    data = data() if callable(data) else data
    response, upstream = await send(json.loads(anthropic_turn("claude-sonnet-5-5", document(data))))

    assert refusal(response) == "privacy-proxy: refused (PDF_UNREADABLE)"
    assert upstream.requests == []


async def test_a_pdf_over_100_pages_is_refused():
    assert len(PdfReader(io.BytesIO(pdf(*["p"] * 100))).pages) == 100
    body = json.loads(anthropic_turn("claude-sonnet-5-5", document(pdf(*["p"] * 101))))
    response, upstream = await send(body)

    assert refusal(response) == "privacy-proxy: refused (PDF_TOO_LONG)"
    assert upstream.requests == []

    # A hundred pages is within the limit.
    response, _ = await send(
        json.loads(anthropic_turn("claude-sonnet-5-5", document(pdf(*["p"] * 100))))
    )
    assert response.status_code == 200


async def test_an_extraction_past_its_time_is_refused(monkeypatch):
    real = detection._pdf_text

    def slow(data, deadline):
        time.sleep(0.5)
        return real(data, deadline)

    monkeypatch.setattr(detection, "PDF_MAX_SECONDS", 0.1)
    monkeypatch.setattr(detection, "_pdf_text", slow)
    started = time.monotonic()
    body = json.loads(anthropic_turn("claude-sonnet-5-5", document(fresh())))
    response, upstream = await send(body)

    assert refusal(response) == "privacy-proxy: refused (PDF_TOO_SLOW)"
    assert upstream.requests == []
    # The caller is answered at the limit, not when the extraction gives up.
    assert time.monotonic() - started < 0.45

    # The wait was the proxy's, not the PDF's: once its own extraction finishes in
    # time, the next turn passes rather than being refused from the cache.
    await asyncio.sleep(0.6)
    response, _ = await send(body)
    assert response.status_code == 200


def test_an_extraction_past_its_own_time_stops_at_the_next_page_and_is_cached(monkeypatch):
    assert detection._pdf_text(b64(pdf("one", "two")), -1) == Detection("PDF_TOO_SLOW", None)

    calls = []
    monkeypatch.setattr(
        detection, "_pdf_text", lambda d, s: calls.append(d) or Detection("PDF_TOO_SLOW", None)
    )
    texts = detection.PdfTexts()
    assert texts.text("slow pdf") == texts.text("slow pdf") == Detection("PDF_TOO_SLOW", None)
    assert len(calls) == 1


def test_the_limits_are_the_decided_ones():
    assert (detection.PDF_MAX_PAGES, detection.PDF_MAX_SECONDS, detection.PDF_CACHE_SIZE) == (
        100,
        2.0,
        64,
    )


# --- The cache: a PDF re-sent on every turn is extracted once ---


async def test_a_pdf_sent_again_is_not_extracted_again(monkeypatch):
    calls = []
    real = detection._pdf_text
    monkeypatch.setattr(detection, "_pdf_text", lambda d, t: calls.append(d) or real(d, t))
    body = json.loads(anthropic_turn("claude-sonnet-5-5", document(fresh())))

    for _ in range(3):
        response, _ = await send(body)
        assert response.status_code == 200
    assert len(calls) == 1


def test_a_refusal_is_cached_as_that_refusal(monkeypatch):
    calls = []
    real = detection._pdf_text
    monkeypatch.setattr(detection, "_pdf_text", lambda d, t: calls.append(d) or real(d, t))
    scanner = Scanner(SCANNER.denylist)
    body = json.loads(anthropic_turn("claude-sonnet-5-5", document(b64(b"not a pdf"))))

    assert scanner.check(body, trusted=True) == [Detection("PDF_UNREADABLE", None)]
    assert scanner.check(body, trusted=True) == [Detection("PDF_UNREADABLE", None)]
    assert len(calls) == 1


def test_the_cache_keeps_the_64_most_recent(monkeypatch):
    monkeypatch.setattr(detection, "_pdf_text", lambda d, t: "")
    texts = detection.PdfTexts()
    for n in range(65):
        texts.text(f"pdf {n}")
    assert len(texts._cache) == 64


# --- Images: passed to a Trusted provider, refused to any other ---


async def test_an_image_passes_to_anthropic(lane):
    response, upstream = await send(json.loads(anthropic_turn("claude-sonnet-5-5", image())))
    assert response.status_code == 200

    body = anthropic_turn("claude-haiku-5-5", image())
    upstream = ok()
    response, _ = await post(lane, upstream, body, path=MESSAGES, **anthropic_headers())
    assert response.status_code == 200
    assert upstream.bodies == [body]


async def test_an_openai_image_passes_to_openai_and_its_data_is_not_read_as_text(lane):
    # Base64 that decodes to nothing, but reads as a personnummer if taken as text.
    url = "data:image/png;base64,191212121212" + "A" * 40
    part = {"type": "image_url", "image_url": {"url": url}}
    upstream = ok()
    response, _ = await post(lane, upstream, openai_turn("gpt-5.6-luna", part))

    assert response.status_code == 200


@pytest.mark.parametrize("model", ["deepseek-flash", "kimi-k3.1-pro"])
@pytest.mark.parametrize(
    "fmt, attached",
    [
        ("anthropic", image()),
        ("anthropic", document(fresh())),
        ("anthropic", {"type": "image", "source": {"type": "url", "url": "https://x.test/a.png"}}),
        ("openai", image_part()),
        ("openai", file_part(fresh())),
        ("openai", {"type": "image_url", "image_url": {"url": "https://x.test/a.png"}}),
    ],
    ids=["image", "pdf", "image-url", "openai-image", "openai-pdf", "openai-image-url"],
)
async def test_an_image_or_pdf_to_a_provider_not_trusted_is_refused(lane, model, fmt, attached):
    upstream = ok()
    if fmt == "anthropic":
        body = anthropic_turn(model, attached)
        response, log = await post(lane, upstream, body, path=MESSAGES, **anthropic_headers())
    else:
        response, log = await post(lane, upstream, openai_turn(model, attached))

    assert message_of(response) == "privacy-proxy: refused (MEDIA_TO_UNTRUSTED)"
    assert upstream.requests == []
    line = json.loads(log.getvalue())
    assert line["detections"] == [{"type": "MEDIA_TO_UNTRUSTED", "hash": None}]


async def test_a_pdf_to_a_provider_not_trusted_is_refused_before_it_is_read(lane, monkeypatch):
    calls = []
    monkeypatch.setattr(detection, "_pdf_text", lambda d, t: calls.append(d) or "")
    upstream = ok()
    body = anthropic_turn("deepseek-flash", document(fresh()))
    response, _ = await post(lane, upstream, body, path=MESSAGES, **anthropic_headers())

    assert message_of(response) == "privacy-proxy: refused (MEDIA_TO_UNTRUSTED)"
    assert calls == []


@pytest.mark.parametrize("kind", [[1], {"a": 1}])
async def test_a_type_that_is_not_a_string_is_still_checked_not_a_500(lane, kind):
    body = json.loads(openai_turn("deepseek-flash"))
    body["messages"][0]["content"].append({"type": kind, "text": f"pnr {PNR}"})
    upstream = ok()
    response, _ = await post(lane, upstream, json.dumps(body).encode())

    assert message_of(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"


async def test_text_alone_still_goes_to_a_provider_not_trusted(lane):
    upstream = ok()
    document_as_text = {
        "type": "document",
        "source": {"type": "text", "media_type": "text/plain", "data": "public notes"},
    }
    body = anthropic_turn("deepseek-flash", document_as_text)
    response, _ = await post(lane, upstream, body, path=MESSAGES, **anthropic_headers())

    assert response.status_code == 200


# --- providers.yaml: every provider says whether it is Trusted ---


def test_the_repo_trusts_anthropic_and_openai_only():
    providers = Providers.load(PROVIDERS_FILE)
    trusted = {
        model: providers.route(model).provider.trusted
        for model in ("claude-haiku-5-5", "gpt-5.6-luna", "deepseek-flash", "kimi-k3.1-pro")
    }
    assert trusted == {
        "claude-haiku-5-5": True,
        "gpt-5.6-luna": True,
        "deepseek-flash": False,
        "kimi-k3.1-pro": False,
    }


@pytest.mark.parametrize("trusted", [None, "yes", 1])
def test_a_provider_without_trusted_stops_the_proxy_at_start_up(
    monkeypatch, tmp_path, capsys, trusted
):
    providers = yaml.safe_load(PROVIDERS_FILE.read_text())
    if trusted is None:
        del providers["providers"]["deepseek"]["trusted"]
    else:
        providers["providers"]["deepseek"]["trusted"] = trusted
    (tmp_path / "providers.yaml").write_text(yaml.safe_dump(providers))
    (tmp_path / "keys.yaml").write_text(json.dumps(KEYS))
    monkeypatch.setenv("KEYS_PATH", str(tmp_path / "keys.yaml"))
    monkeypatch.setenv("PROVIDERS_PATH", str(tmp_path / "providers.yaml"))
    monkeypatch.setenv("SPEND_DB_PATH", str(tmp_path / "spend.db"))

    with pytest.raises(SystemExit) as stopped:
        cli.load_api_lane()
    assert "provider 'deepseek': trusted is not true or false" in str(stopped.value)
