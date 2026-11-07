import urllib.request, re, json, zipfile, pathlib, hashlib

root = pathlib.Path(__file__).parent
for folder in ("runtime", "models", "data"):
    (root / folder).mkdir(exist_ok=True)


def download(url, path):
    if not path.exists():
        print("Downloading", url, flush=True)
        urllib.request.urlretrieve(url, path)
    return path


release = "https://github.com/ggml-org/llama.cpp/releases/tag/b12110"
assets = (
    urllib.request.urlopen(release.replace("/tag/", "/expanded_assets/"))
    .read()
    .decode()
)
if "win-cpu-x64" not in assets:
    tag = (
        urllib.request.urlopen(
            release.replace("/tag/", "/download/") + "/nightly-tag.txt"
        )
        .read()
        .decode()
        .strip()
    )
    release = "https://github.com/ggml-org/llama.cpp/releases/tag/" + tag
    assets = (
        urllib.request.urlopen(release.replace("/tag/", "/expanded_assets/"))
        .read()
        .decode()
    )
links = re.findall('href="([^"]+)"', assets)
link = next(x for x in links if "win-cpu-x64" in x and x.endswith(".zip"))
archive = download("https://github.com" + link, root / "runtime" / "llama.zip")
with zipfile.ZipFile(archive) as z:
    z.extractall(root / "runtime")
repo = "unsloth/Qwen3.5-2B-GGUF"
meta = json.load(urllib.request.urlopen("https://huggingface.co/api/models/" + repo))
name = next(
    x["rfilename"] for x in meta["siblings"] if x["rfilename"].endswith("Q4_K_M.gguf")
)
meta["sha"] = "f6d5376be1edb4d416d56da11e5397a961aca8ae"
model = download(
    "https://huggingface.co/" + repo + "/resolve/" + meta["sha"] + "/" + name,
    root / "models" / "model-2b.gguf",
)
manifest = {
    "runtime_release": release,
    "model_repo": repo,
    "revision": meta["sha"],
    "filename": name,
    "sha256": hashlib.file_digest(model.open("rb"), "sha256").hexdigest(),
}
(root / "models" / "manifest.json").write_text(json.dumps(manifest, indent=2))
(root / "MODEL_MANIFEST.json").write_text(json.dumps(manifest, indent=2))
if (
    manifest["sha256"]
    != "aaf42c8b7c3cab2bf3d69c355048d4a0ee9973d48f16c731c0520ee914699223"
):
    raise RuntimeError("Model checksum mismatch; do not run the downloaded file")
print(json.dumps(manifest, indent=2))
