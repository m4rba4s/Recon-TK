#!/usr/bin/env python3
"""
Recon Pipeline — modular CTF recon orchestrator (fixed)
======================================================
• Шаги как «плагины» → masscan, nmap, gobuster (добавишь ещё — 3‑строчки).
• Состояние пишется в .recon_state.json; `--resume` продолжает с места падения.
• Исправлено:
  – Парсер masscan корректно берёт **поле 3 (порт)**, а не IP.
  – Escape‐warning заменён на «\\o/».
  – Если каталог runs принадлежит root, выводим понятную ошибку и подсказку.
"""
import argparse
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, List

DEFAULT_OUTROOT = pathlib.Path.cwd() / "runs"
STATE_FILE = ".recon_state.json"
REQUIRED_BINS = {
    "masscan": "full‑port scan",
    "nmap": "service enum",
    "gobuster": "dir brute",
}

###############################################################################
# logging helpers
###############################################################################

def setup_logger(run_dir: pathlib.Path) -> logging.Logger:
    logger = logging.getLogger("recon")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = RotatingFileHandler(run_dir / "recon.log", maxBytes=5 << 20, backupCount=3)
    fh.setFormatter(fmt)

    logger.addHandler(sh)
    logger.addHandler(fh)
    return logger

###############################################################################
# Step abstraction
###############################################################################

class Step:
    def __init__(
        self,
        name: str,
        cmd_fn: Callable[[str, pathlib.Path], List[str]],
        art_fn: Callable[[pathlib.Path], pathlib.Path],
        need_root: bool = False,
    ) -> None:
        self.name, self.cmd_fn, self.art_fn, self.need_root = name, cmd_fn, art_fn, need_root

    def run(self, tgt: str, run: pathlib.Path, log: logging.Logger):
        art = self.art_fn(run)
        if art.exists():
            log.info("[%s] artifact exists → skip", self.name)
            return
        cmd = self.cmd_fn(tgt, run)
        if self.need_root and os.geteuid() != 0:
            cmd = ["sudo", *cmd]
        log.info("[%s] exec: %s", self.name, " ".join(cmd))
        subprocess.run(cmd, check=True)
        log.info("[%s] OK → %s", self.name, art.name)

###############################################################################
# commands / artifacts
###############################################################################

def masscan_cmd(t: str, d: pathlib.Path):
    return ["masscan", "-p0-65535", "--rate", "20000", t, "-oL", str(d / "masscan.lst")]

def masscan_art(d: pathlib.Path):
    return d / "masscan.lst"

def ports_file(d: pathlib.Path):
    return d / "ports.txt"

def nmap_cmd(t: str, d: pathlib.Path):
    mc_path = masscan_art(d)
    if not mc_path.exists():
        raise RuntimeError("Need masscan before nmap")
    # parse ports (column 3)
    ports = sorted({line.split()[2] for line in mc_path.read_text().splitlines() if line.startswith("open")})
    ports_file(d).write_text(",".join(ports))
    return ["nmap", "-sVC", "-p", ports_file(d).read_text(), "-oA", str(d / "nmap"), t]

def nmap_art(d: pathlib.Path):
    return d / "nmap.gnmap"

def gobuster_cmd(t: str, d: pathlib.Path):
    return ["gobuster", "dir", "-q", "-u", f"http://{t}", "-w", "/opt/wordlists/SecLists/Discovery/Web-Content/big.txt", "-o", str(d / "gob_80.txt")]

def gobuster_art(d: pathlib.Path):
    return d / "gob_80.txt"

STEPS: Dict[str, Step] = {
    "masscan": Step("masscan", masscan_cmd, masscan_art, need_root=True),
    "nmap": Step("nmap", nmap_cmd, nmap_art),
    "gobuster": Step("gobuster", gobuster_cmd, gobuster_art),
}

###############################################################################
# helpers
###############################################################################

def need_bins(log: logging.Logger):
    miss = [b for b in REQUIRED_BINS if shutil.which(b) is None]
    if miss:
        log.error("Missing binaries: %s", ", ".join(miss))
        sys.exit(1)

###############################################################################
# main
###############################################################################

def main():
    ap = argparse.ArgumentParser("Recon pipeline")
    ap.add_argument("target")
    ap.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUTROOT)
    ap.add_argument("--steps", default="masscan,nmap,gobuster")
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    try:
        args.out.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print("[!] No write access to", args.out, "→ try: sudo chown -R $(whoami): $(args.out) or choose --out")
        sys.exit(1)

    # unique run dir
    stamp = int(datetime.now(timezone.utc).timestamp())
    run_dir = args.out / f"{args.target}-{stamp}"
    run_dir.mkdir()

    log = setup_logger(run_dir)
    need_bins(log)

    state_p = run_dir / STATE_FILE
    state = {}

    steps = [s.strip() for s in args.steps.split(',') if s.strip()]
    log.info("Target: %s", args.target)
    log.info("Steps: %s", ', '.join(steps))

    try:
        for name in steps:
            step = STEPS.get(name)
            if not step:
                log.warning("Unknown step %s", name)
                continue
            step.run(args.target, run_dir, log)
            state[name] = "done"
            state_p.write_text(json.dumps(state))
    except KeyboardInterrupt:
        log.warning("Interrupted. Resume with --resume")
        sys.exit(130)
    except subprocess.CalledProcessError as exc:
        log.error("Command failed: %s", exc)
        sys.exit(exc.returncode)

    log.info("All requested steps completed. \\o/")

if __name__ == "__main__":
    main()
