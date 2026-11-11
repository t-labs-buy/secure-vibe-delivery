"""Scenes for the Secure Vibe Delivery tutorial — one function per "app" scene in scenes.json.

The screen is the ArchFlow demo (a local, offline HTML file). Every scene runs in a fresh browser,
so each one first jumps the demo to where the previous scene ended (by clicking the timeline
scrubber at that step), then advances with the Step button on its cues. Nothing is written
anywhere: the demo only animates.
"""
import os

from demo import *  # noqa: F401,F403
from demo import glide, hold, settle, point, to, wait_enabled, W, H  # noqa: F401

BASE_URL = os.environ.get(
    "DEMO_URL",
    "file:///Users/senthilpalanivelu/Programme/secure-vibe-delivery/docs/architecture/demo/index.html",
)
STAGE_MAX_X = 1500   # the activity log starts to the right of this; keep point() on the diagram
SPEED = 2.0          # each step ~1.6 s, a there-and-back step ~3.4 s

WIDEN = """
:has(> .archflow-container) { max-width: none !important; }   /* lift the demo's 1500 px cap */
.archflow-container { margin: 0 14px !important; }
html, body { overflow: hidden !important; }
"""


def login(pg):
    """No sign-in: the demo is a static page."""


def _speed(pg, target):
    for _ in range(30):
        txt = pg.locator("text=/\\d\\.\\d+×/").first.inner_text()
        cur = float(txt.rstrip("×"))
        if abs(cur - target) < 0.01:
            return
        pg.locator("button", has_text="+" if cur < target else "−").first.click()
        pg.wait_for_timeout(50)


def open_demo(pg, done=0):
    """Open the demo, widen it, set the speed, and jump to the state after `done` steps."""
    pg.goto(BASE_URL)
    settle(pg, 1.2)
    pg.add_style_tag(content=WIDEN)
    pg.wait_for_timeout(400)
    _speed(pg, SPEED)
    if done:
        seg = pg.locator(".scrub-seg").nth(done - 1).bounding_box()
        pg.mouse.click(seg["x"] + seg["width"] / 2, seg["y"] + seg["height"] / 2)
        pg.wait_for_timeout(900)
    pg.evaluate("window.scrollTo(0, 0)")
    glide(pg, W * 0.45, H * 0.55, steps=5)


def step(pg):
    """Press Step once the previous step's animation has finished."""
    btn = pg.locator("button:has-text('Step')")
    wait_enabled(pg, btn, timeout=12)
    btn.click()
    pg.evaluate("window.scrollTo(0, 0)")


def card(pg, title, dx=0, dy=0):
    point(pg, title, max_x=STAGE_MAX_X, dx=dx, dy=dy)


def s01_idea(pg, mark, at):
    open_demo(pg)
    mark()
    at("is it safe")
    card(pg, "Security Check")
    at("does it work")
    card(pg, "Functional Check")
    at("can it cope")
    card(pg, "Performance")
    at("gives one verdict")
    card(pg, "Go-Live Gate")


def s02_cast(pg, mark, at):
    open_demo(pg)
    mark()
    at("It's an MCP server")
    card(pg, "MCP Server")
    at("You ask your AI assistant")
    card(pg, "Developer")
    hold(pg, 1.2)
    card(pg, "AI Assistant")
    at("the assistant calls")
    card(pg, "MCP Server")
    at("Everything runs on your own machine")
    card(pg, "Snyk CLI")
    hold(pg, 1.0)
    card(pg, "pytest / Jest")
    hold(pg, 0.8)
    card(pg, "Locust")


def s03_ask(pg, mark, at):
    open_demo(pg, 0)
    mark()
    at("The developer asks")
    step(pg)
    at("First, the assistant calls")
    step(pg)
    at("which confirms")
    step(pg)
    card(pg, "Doctor")


def s04_run(pg, mark, at):
    open_demo(pg, 3)
    mark()
    at("Then it starts the run")
    step(pg)
    at("It starts a background job")
    step(pg)
    card(pg, "Run Pipeline")
    at("hands back a run ID")
    step(pg)
    card(pg, "AI Assistant")


def s05_security(pg, mark, at):
    open_demo(pg, 6)
    mark()
    at("Security comes first")
    step(pg)
    at("runs the Snyk scans")
    step(pg)
    card(pg, "Snyk CLI")
    at("They look for")
    step(pg)
    card(pg, "Snyk · Semgrep")
    at("It also checks")
    step(pg)
    at("which catches")
    step(pg)
    card(pg, "PyPI")
    at("In this example")
    step(pg)
    card(pg, "Security Check")


def s06_function(pg, mark, at):
    open_demo(pg, 12)
    mark()
    at("the functional check runs")
    step(pg)
    at("and measures coverage")
    step(pg)
    card(pg, "pytest / Jest")
    at("Here it's eighty-two")
    step(pg)
    card(pg, "Functional Check")
    at("Meanwhile")
    step(pg)
    card(pg, "AI Assistant")


def s07_load(pg, mark, at):
    open_demo(pg, 16)
    mark()
    at("Then performance")
    step(pg)
    at("Locust sends")
    step(pg)
    card(pg, "Locust")
    at("to a test copy")
    step(pg)
    card(pg, "Test Environment")
    at("A quick run")
    step(pg)
    at("a fifteen-minute gate run")
    step(pg)
    card(pg, "Performance")


def s08_verdict(pg, mark, at):
    open_demo(pg, 21)
    mark()
    card(pg, "Go-Live Gate")
    at("Now the gate decides")
    step(pg)
    at("means no-go")
    step(pg)
    card(pg, "Report Renderer")
    at("The report renderer writes")
    step(pg)
    card(pg, "Run Records")
    at("and opens it")
    step(pg)
    card(pg, "Developer")


def s09_fix(pg, mark, at):
    open_demo(pg, 25)
    mark()
    at("the assistant fetches")
    step(pg)
    at("Each item links")
    step(pg)
    card(pg, "Skills")
    at("so the assistant can explain")
    step(pg)
    card(pg, "AI Assistant")


EDGE_MID_JS = """() => {
  const hit = [...document.querySelectorAll('path.edge-hit')].find(p =>
    (p.querySelector('title') || {}).textContent?.startsWith('Security Check ⇄ Snyk CLI'));
  if (!hit) return null;
  const m = hit.getPointAtLength(hit.getTotalLength() / 2);
  const pt = hit.ownerSVGElement.createSVGPoint(); pt.x = m.x; pt.y = m.y;
  const s = pt.matrixTransform(hit.getScreenCTM());
  return {x: s.x, y: s.y};
}"""


def s10_key(pg, mark, at):
    open_demo(pg, 28)
    mark()
    at("the server never calls")
    mid = pg.evaluate(EDGE_MID_JS)
    if mid:
        glide(pg, mid["x"], mid["y"])
        hold(pg, 0.4)
        pg.mouse.click(mid["x"], mid["y"])
    at("It runs the Snyk")
    card(pg, "Snyk CLI")
    at("So a check only works")
    close = pg.locator(".inspector-close")
    if close.count():
        to(pg, close.first)
        hold(pg, 0.4)
        close.first.click()
    card(pg, "pytest / Jest")
