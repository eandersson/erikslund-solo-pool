"""Operator dashboard at `/`, rendered with PEP 750 t-strings.

`render()` HTML-escapes every interpolation, so miner-supplied strings in stats
are safe-by-construction.
"""

import time
from html import escape
from string.templatelib import Interpolation
from string.templatelib import Template

from erikslund_pool.poolstatus import suffix_string


def render(template: Template) -> str:
    """Render a t-string template to HTML, escaping every interpolated value."""
    parts: list[str] = []
    for item in template:
        if isinstance(item, Interpolation):
            parts.append(escape(str(item.value)))
        else:
            parts.append(item)
    return "".join(parts)


def _format_hashrate(hashes_per_second: float) -> str:
    for unit in ("H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"):
        if hashes_per_second < 1000:
            return f"{hashes_per_second:.2f} {unit}"
        hashes_per_second /= 1000
    return f"{hashes_per_second:.2f} ZH/s"


def _format_duration(seconds: int) -> str:
    """Seconds -> e.g. '1d 1h 1m 1s' (highest non-zero unit down to seconds)."""
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m {secs}s"
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _format_height(height) -> str:
    """Abbreviated height with the raw value in parens, e.g. '88.5K (88,531)'."""
    if height is None:
        return "--"
    if height < 1000:
        return f"{height:,}"
    return f"{suffix_string(height)} ({height:,})"


def _format_difficulty(difficulty) -> str:
    """Abbreviated difficulty + raw value in parens (like height). '--' if unknown; a
    plain :.4g for sub-1 values (e.g. regtest) where K/M/G abbreviation is meaningless."""
    if difficulty is None:
        return "--"
    if difficulty < 1:
        return f"{difficulty:.4g}"
    if difficulty < 1000:
        return f"{round(difficulty):,}"
    return f"{suffix_string(difficulty)} ({round(difficulty):,})"


def render_dashboard(pool) -> str:
    status = pool.status()
    pool_stats = pool.pool_stats()
    generator_stats = pool.generator_stats()
    windows = pool.hashrate_windows(time.monotonic())

    ready_text = "READY" if status["ready"] else "NOT READY"
    ready_class = "ok" if status["ready"] else "bad"
    network_difficulty_text = _format_difficulty(pool_stats["network_diff"])
    height_text = _format_height(pool_stats["height"])
    chain_text = generator_stats["chain"] or "--"
    uptime_text = _format_duration(status["uptime"])
    last_block_text = pool_stats["last_block_found"] or "never"
    best_share_text = _format_difficulty(pool_stats["best_share"])
    # Decaying-average hashrate per window: diff/s * 2^32 = H/s.
    hr_1m = _format_hashrate(windows[60] * 2 ** 32)
    hr_5m = _format_hashrate(windows[300] * 2 ** 32)
    hr_15m = _format_hashrate(windows[900] * 2 ** 32)
    hr_1h = _format_hashrate(windows[3600] * 2 ** 32)

    page = t"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>{status["name"]} -- solo pool</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:46rem;color:#222}}
h1{{font-size:1.4rem;margin-bottom:.2rem}} small{{color:#888;font-weight:400}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
td{{padding:.3rem .8rem;border-bottom:1px solid #e5e5e5}}
td:first-child{{color:#777;width:14rem}} .ok{{color:#0a7d28}} .bad{{color:#c0392b}}
a{{color:#2563eb;text-decoration:none}}
</style></head>
<body>
<h1>{status["name"]} <small>v{status["version"]} | pid {status["pid"]}</small></h1>
<p class="{ready_class}"><strong>{ready_text}</strong></p>
<table>
<tr><td>chain</td><td>{chain_text}</td></tr>
<tr><td>height</td><td>{height_text}</td></tr>
<tr><td>network difficulty</td><td>{network_difficulty_text}</td></tr>
<tr><td>blocks found</td><td>{pool_stats["blocks_found"]}</td></tr>
<tr><td>last block found</td><td>{last_block_text}</td></tr>
<tr><td>shares accepted</td><td>{pool_stats["shares_accepted"]}</td></tr>
<tr><td>shares rejected</td><td>{pool_stats["shares_rejected"]}</td></tr>
<tr><td>best share</td><td>{best_share_text}</td></tr>
<tr><td>connected workers</td><td>{pool_stats["workers"]}</td></tr>
<tr><td>distinct addresses</td><td>{pool_stats["users"]}</td></tr>
<tr><td>hashrate (1m)</td><td>{hr_1m}</td></tr>
<tr><td>hashrate (5m)</td><td>{hr_5m}</td></tr>
<tr><td>hashrate (15m)</td><td>{hr_15m}</td></tr>
<tr><td>hashrate (1hr)</td><td>{hr_1h}</td></tr>
<tr><td>uptime</td><td>{uptime_text}</td></tr>
</table>
<p><a href="/status">/status</a> | <a href="/stats/pool">/stats/pool</a>
 | <a href="/metrics">/metrics</a></p>
</body></html>"""
    return render(page)
