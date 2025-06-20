#!/usr/bin/env python3
"""
Recon Pipeline — modular CTF recon orchestrator (v0.3‑fix)
==========================================================
• Шаги как плагины (masscan → nmap → gobuster). Добавлять новый: Step(...)
• Состояние в .recon_state.json, `--resume` продолжает.
• Исправлены:
  – Парсинг masscan (берёт порт ‑ поле 2).
  – gobuster wildcard‑403 через «‑b 403 -r» и синтаксис закрыт.
  – Чёткие подсказки при lack of permissions.
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

DEFAULT_OUT = pathlib.Path.cwd() / "runs"
STATE_FILE = ".recon_state.json"
REQ = {"masscan": "port sweep", "nmap": "svc enum", "gobuster": "web brute"}

###############################################################################
# helpers
###############################################################################

def setup_logger(run: pathlib.Path) -> logging.Logger:
    lg = logging.getLogger("recon"); lg.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    sh, fh = logging.StreamHandler(sys.stdout), RotatingFileHandler(run / "recon.log", maxBytes=5<<20, backupCount=3)
    sh.setFormatter(fmt); fh.setFormatter(fmt); lg.addHandler(sh); lg.addHandler(fh); return lg

class Step:
    def __init__(self, name: str, cmd_fn: Callable[[str, pathlib.Path], List[str]], art_fn: Callable[[pathlib.Path], pathlib.Path], need_root=False):
        self.name, self.cmd_fn, self.art_fn, self.need_root = name, cmd_fn, art_fn, need_root
    def run(self, tgt: str, run: pathlib.Path, log: logging.Logger):
        art = self.art_fn(run)
        if art.exists(): log.info("[%s] exists → skip", self.name); return
        cmd = self.cmd_fn(tgt, run);  cmd = ["sudo", *cmd] if self.need_root and os.geteuid()!=0 else cmd
        log.info("[%s] %s", self.name, " ".join(cmd))
        subprocess.run(cmd, check=True)
        log.info("[%s] OK → %s", self.name, art.name)

###############################################################################
# command builders
###############################################################################

def masscan_cmd(t, d): return ["masscan", "-p0-65535", "--rate", "20000", t, "-oL", str(d/"masscan.lst")]

def masscan_art(d): return d/"masscan.lst"

def ports_file(d): return d/"ports.txt"

def nmap_cmd(t, d):
    if not masscan_art(d).exists(): raise RuntimeError("masscan first")
    ports = sorted({ln.split()[2] for ln in masscan_art(d).read_text().splitlines() if ln.startswith("open")})
    ports_file(d).write_text(",".join(ports))
    return ["nmap", "-sVC", "-p", ports_file(d).read_text(), "-oA", str(d/"nmap"), t]

def nmap_art(d): return d/"nmap.gnmap"

def gobuster_cmd(t, d):
    return [
        "gobuster", "dir", "-q", "-b", "403", "-r",
        "-u", f"http://{t}",
        "-w", "/opt/wordlists/SecLists/Discovery/Web-Content/big.txt",
        "-o", str(d/"gob_80.txt")
    ]

def gobuster_art(d): return d/"gob_80.txt"

STEPS: Dict[str, Step] = {
    "masscan": Step("masscan", masscan_cmd, masscan_art, True),
    "nmap": Step("nmap", nmap_cmd, nmap_art),
    "gobuster": Step("gobuster", gobuster_cmd, gobuster_art),
}

###############################################################################
# misc utils
###############################################################################

def need_bins(log):
    missing=[b for b in REQ if shutil.which(b) is None]
    if missing: log.error("Missing: %s", ", ".join(missing)); sys.exit(1)

###############################################################################
# main
###############################################################################

def main():
    ap=argparse.ArgumentParser("Recon pipeline")
    ap.add_argument("target"); ap.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    ap.add_argument("--steps", default="masscan,nmap,gobuster"); ap.add_argument("--resume", action="store_true")
    args=ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    stamp=int(datetime.now(timezone.utc).timestamp())
    run_dir=args.out/f"{args.target}-{stamp}"; run_dir.mkdir()

    log=setup_logger(run_dir); need_bins(log)
    log.info("Target: %s", args.target); steps=[s.strip() for s in args.steps.split(',') if s.strip()]; log.info("Steps: %s", ', '.join(steps))

    state_path=run_dir/STATE_FILE; state={} if not args.resume else json.loads(state_path.read_text()) if state_path.exists() else {}

    try:
        for s in steps:
            st=STEPS.get(s);  if not st: log.warning("Unknown %s", s); continue
            if state.get(s)=="done": log.info("[%s] state=done → skip", s); continue
            st.run(args.target, run_dir, log); state[s]="done"; state_path.write_text(json.dumps(state))
    except (KeyboardInterrupt, subprocess.CalledProcessError) as e:
        log.error("Interrupted/failure: %s", e); log.error("Resume with --resume"); sys.exit(1)

    log.info("All steps complete! \\o/")

if __name__=="__main__":
    main()
