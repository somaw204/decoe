import ast
import io
import marshal
import pathlib
import re
import shutil
import subprocess
import tempfile
import dis


def _load_payload() -> bytes:
    """Extract marshalled bytecode from enc.py."""
    text = pathlib.Path("enc.py").read_text()
    match = re.search(r"marshal.loads\((b'.*')\)", text)
    if not match:
        raise RuntimeError("marshal payload not found in enc.py")
    return ast.literal_eval(match.group(1))


def _attempt_decompile(data: bytes) -> str:
    """Try to decompile bytecode using pycdc; fall back to disassembly."""
    pycdc = shutil.which("pycdc")
    if pycdc:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp.flush()
            try:
                result = subprocess.run(
                    [pycdc, "-c", "-v", "3.10", tmp.name],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return result.stdout
            except subprocess.CalledProcessError:
                pass
    code_obj = marshal.loads(data)
    buf = io.StringIO()
    dis.dis(code_obj, file=buf)
    return buf.getvalue()


def main() -> None:
    payload = _load_payload()
    decoded = _attempt_decompile(payload)
    pathlib.Path("decoded_output.py").write_text(decoded)
    print("Wrote decoded_output.py")


if __name__ == "__main__":
    main()
