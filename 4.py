#!/usr/bin/env python3
"""
Recon Pipeline — modular CTF recon orchestrator (v0.4)
-----------------------------------------------------
Fixed syntax errors, tidy loop, safer parsing.
"""
import argparse, json, logging, os, pathlib, shutil, subprocess, sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, List

DEFAULT_OUT = pathlib.Path.cwd() / "runs"
STATE_FILE = ".recon_state.json"
REQ = {"masscan": "port sweep", "nmap": "svc enum", "gobuster": "dir brute"}

###############################################################################
# helpers
###############################################################################

def logger_for(run: pathlib.Path):
    lg = logging.getLogger("recon"); lg.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    sh, fh = logging.StreamHandler(sys.stdout), RotatingFileHandler(run/"recon.log", maxBytes=5<<20, backupCount=2)
    sh.setFormatter(fmt); fh.setFormatter(fmt)
    lg.addHandler(sh); lg.addHandler(fh); return lg

class Step:
    def __init__(self, name:str, cmd_fn:Callable[[str, pathlib.Path],List[str]], art_fn:Callable[[pathlib.Path],pathlib.Path], need_root=False):
        self.name, self.cmd_fn, self.art_fn, self.need_root = name, cmd_fn, art_fn, need_root
    def run(self, tgt:str, run:pathlib.Path, lg:logging.Logger):
        art=self.art_fn(run)
        if art.exists(): lg.info("[%s] exists → skip", self.name); return
        cmd=self.cmd_fn(tgt, run)
        if self.need_root and os.geteuid()!=0: cmd=["sudo", *cmd]
        lg.info("[%s] %s", self.name, " ".join(cmd))
        subprocess.run(cmd, check=True)
        lg.info("[%s] OK → %s", self.name, art.name)

###############################################################################
# step command builders
###############################################################################

def masscan_cmd(t,d): return ["masscan","-p0-65535","--rate","20000",t,"-oL",str(d/"masscan.lst")]

def masscan_art(d): return d/"masscan.lst"


def ports_file(d): return d/"ports.txt"

def nmap_cmd(t,d):
    if not masscan_art(d).exists(): raise RuntimeError("Run masscan first")
    ports=sorted({ln.split()[2] for ln in masscan_art(d).read_text().splitlines() if ln.startswith("open")})
    ports_file(d).write_text(",".join(ports))
    return ["nmap","-sVC","-p",ports_file(d).read_text(),"-oA",str(d/"nmap"),t]

def nmap_art(d): return d/"nmap.gnmap"


def gobuster_cmd(t,d):
    return ["gobuster","dir","-q","-b","403","-r","-u",f"http://{t}","-w","/opt/wordlists/SecLists/Discovery/Web-Content/big.txt","-o",str(d/"gob_80.txt")]

def gobuster_art(d): return d/"gob_80.txt"

STEPS: Dict[str, Step] = {
    "masscan": Step("masscan", masscan_cmd, masscan_art, True),
    "nmap": Step("nmap", nmap_cmd, nmap_art),
    "gobuster": Step("gobuster", gobuster_cmd, gobuster_art),
}

###############################################################################
# misc utils
###############################################################################

def need_bins(lg):
    miss=[b for b in REQ if shutil.which(b) is None]
    if miss:
        lg.error("Missing binaries: %s", ", ".join(miss)); sys.exit(1)

###############################################################################
# main
###############################################################################

def main():
    ap=argparse.ArgumentParser("Recon pipeline")
    ap.add_argument("target"); ap.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    ap.add_argument("--steps", default="masscan,nmap,gobuster"); ap.add_argument("--resume", action="store_true")
    args=ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    ts=int(datetime.now(timezone.utc).timestamp())
    run=args.out/f"{args.target}-{ts}"; run.mkdir()

    lg=logger_for(run); need_bins(lg)
    lg.info("Target: %s", args.target)

    steps=[s.strip() for s in args.steps.split(',') if s.strip()]
    lg.info("Steps: %s", ', '.join(steps))

    state_p=run/STATE_FILE
    state={} if not args.resume else (json.loads(state_p.read_text()) if state_p.exists() else {})

    try:
        for name in steps:
            st=STEPS.get(name)
            if not st:
                lg.warning("Unknown step %s", name); continue
            if state.get(name)=="done":
                lg.info("[%s] state=done → skip", name); continue
            st.run(args.target, run, lg)
            state[name]="done"; state_p.write_text(json.dumps(state))
    except (KeyboardInterrupt, subprocess.CalledProcessError) as e:
        lg.error("Abort: %s", e); lg.error("Resume with --resume"); sys.exit(1)

    lg.info("All steps complete! \\o/")

if __name__=="__main__":
    main()
