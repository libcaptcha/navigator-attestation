from __future__ import annotations

import subprocess
import time
import os
from typing import Any

import pytest

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "server.js")
PORT = 3458
BASE_URL = f"http://localhost:{PORT}"
WAIT_TIMEOUT = 15


@pytest.fixture(scope="module")
def server() -> str:
    proc = subprocess.Popen(
        ["node", SERVER_SCRIPT],
        env={**os.environ, "PORT": str(PORT)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stdout.readline().decode().strip()
        if f"READY:{PORT}" in line:
            break
        time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("test server did not start")
    yield BASE_URL
    proc.terminate()
    try:
        _ = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def get_attestation(driver: Any) -> dict[str, Any]:
    driver.get(BASE_URL)
    deadline = time.time() + WAIT_TIMEOUT
    while time.time() < deadline:
        result = driver.execute_script("return window.__attestResult")
        if result is not None:
            return result
        time.sleep(0.3)
    raise TimeoutError("attestation did not complete")


def get_signals(driver: Any) -> dict[str, Any]:
    return driver.execute_script("return window.__signals") or {}


def print_details(
    result: dict[str, Any],
    signals: dict[str, Any],
    name: str,
) -> None:
    score = result.get("score", -1)
    verdict = result.get("verdict", "unknown")
    flags = result.get("flags", [])
    cats = result.get("categoryScores", {})
    print(f"\n  {'─' * 56}")
    print(f"  {name}")
    print(f"  score={score}  verdict={verdict}")
    print(f"  flags ({len(flags)}): {', '.join(flags)}")
    if cats:
        penalized = {
            k: v
            for k, v in cats.items()
            if isinstance(v, dict) and v.get("score", 1) < 1
        }
        if penalized:
            print("  category penalties:")
            for cat, info in sorted(penalized.items()):
                cat_score = info.get("score", "?")
                cat_flags = info.get("flags", [])
                print(f"    {cat}: {cat_score}" f" [{', '.join(cat_flags)}]")
    sig_keys = sorted(signals.keys()) if signals else []
    if sig_keys:
        print(f"  signals collected: {', '.join(sig_keys)}")
    print(f"  {'─' * 56}")


def assert_detected(
    result: dict[str, Any],
    name: str,
    max_score: float = 0.85,
) -> None:
    assert result is not None, f"{name}: no result"
    assert "error" not in result, f"{name}: error: {result.get('error')}"
    score = result["score"]
    verdict = result["verdict"]
    flags = result["flags"]
    assert score < max_score, f"{name}: score {score} >= {max_score}"
    assert verdict != "trusted", f"{name}: should not be trusted"
    assert len(flags) > 0, f"{name}: should have at least one flag"


class TestSeleniumDetection:
    def _make_driver(self, options: Any) -> Any:
        from selenium import webdriver

        return webdriver.Chrome(options=options)

    def test_headless_default(self, server: str) -> None:
        from selenium.webdriver.chrome.options import (
            Options,
        )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = self._make_driver(options)
        try:
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "selenium-headless-default",
            )
            assert_detected(result, "selenium-headless-default", 0.65)
        finally:
            driver.quit()

    def test_headless_with_antidetect_args(
        self,
        server: str,
    ) -> None:
        from selenium.webdriver.chrome.options import (
            Options,
        )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=" + "AutomationControlled")
        options.add_argument("--disable-infobars")
        options.add_argument("--window-size=1920,1080")
        driver = self._make_driver(options)
        try:
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "selenium-antidetect-args",
            )
            assert_detected(result, "selenium-antidetect-args", 0.75)
        finally:
            driver.quit()

    def test_headless_exclude_switches(
        self,
        server: str,
    ) -> None:
        from selenium.webdriver.chrome.options import (
            Options,
        )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=" + "AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        driver = self._make_driver(options)
        try:
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "selenium-exclude-switches",
            )
            assert_detected(
                result,
                "selenium-exclude-switches",
                0.75,
            )
        finally:
            driver.quit()

    def test_headless_custom_ua(
        self,
        server: str,
    ) -> None:
        from selenium.webdriver.chrome.options import (
            Options,
        )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(
            "--user-agent=Mozilla/5.0 "
            + "(X11; Linux x86_64) "
            + "AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/120.0.0.0 Safari/537.36"
        )
        driver = self._make_driver(options)
        try:
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "selenium-custom-ua",
            )
            assert_detected(result, "selenium-custom-ua", 0.75)
        finally:
            driver.quit()

    def test_headless_navigator_override(
        self,
        server: str,
    ) -> None:
        from selenium.webdriver.chrome.options import (
            Options,
        )
        from selenium import webdriver

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=" + "AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        driver = webdriver.Chrome(options=options)
        try:
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": """
                        Object.defineProperty(
                            navigator, 'webdriver',
                            { get: () => undefined }
                        );
                        Object.defineProperty(
                            navigator,
                            'hardwareConcurrency',
                            { get: () => 8 }
                        );
                        Object.defineProperty(
                            navigator, 'languages',
                            {
                                get: () => [
                                    'en-US', 'en'
                                ]
                            }
                        );
                    """},
            )
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "selenium-navigator-override",
            )
            assert_detected(
                result,
                "selenium-navigator-override",
                0.85,
            )
        finally:
            driver.quit()

    def test_headless_full_stealth_attempt(
        self,
        server: str,
    ) -> None:
        from selenium.webdriver.chrome.options import (
            Options,
        )
        from selenium import webdriver

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=" + "AutomationControlled")
        options.add_argument("--window-size=1920,1080")
        options.add_experimental_option(
            "excludeSwitches",
            ["enable-automation", "enable-logging"],
        )
        options.add_experimental_option("useAutomationExtension", False)
        driver = webdriver.Chrome(options=options)
        try:
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": """
                        Object.defineProperty(
                            navigator, 'webdriver',
                            { get: () => undefined }
                        );
                        Object.defineProperty(
                            navigator,
                            'hardwareConcurrency',
                            { get: () => 8 }
                        );
                        Object.defineProperty(
                            navigator, 'deviceMemory',
                            { get: () => 8 }
                        );
                        Object.defineProperty(
                            navigator, 'languages',
                            {
                                get: () => [
                                    'en-US', 'en'
                                ]
                            }
                        );
                        window.chrome = {
                            runtime: {
                                sendMessage: () => {},
                                connect: () => {},
                            },
                            csi: () => ({}),
                            loadTimes: () => ({}),
                            app: {isInstalled: false},
                        };
                    """},
            )
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "selenium-full-stealth",
            )
            assert_detected(
                result,
                "selenium-full-stealth",
                0.85,
            )
        finally:
            driver.quit()


try:
    import undetected_chromedriver as _uc

    has_uc = True
except ImportError:
    _uc = None
    has_uc = False


def _detect_chrome_major() -> int | None:
    for binary in [
        "google-chrome",
        "chromium",
        "chromium-browser",
    ]:
        try:
            out = subprocess.run(
                [binary, "--version"],
                capture_output=True,
                text=True,
            )
            if out.returncode == 0:
                parts = out.stdout.strip().split()
                for part in parts:
                    if "." in part:
                        return int(part.split(".")[0])
        except FileNotFoundError:
            continue
    return None


CHROME_MAJOR = _detect_chrome_major()


@pytest.mark.skipif(
    not has_uc,
    reason="undetected-chromedriver not installed",
)
class TestUndetectedChromeDriver:
    def _make_uc(
        self,
        options: Any,
        **kwargs: Any,
    ) -> Any:
        assert _uc is not None
        return _uc.Chrome(
            options=options,
            version_main=CHROME_MAJOR,
            **kwargs,
        )

    def test_default_headless(
        self,
        server: str,
    ) -> None:
        assert _uc is not None
        options = _uc.ChromeOptions()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = self._make_uc(options, headless=True)
        try:
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "uc-headless-default",
            )
            assert_detected(result, "uc-headless-default", 0.85)
        finally:
            driver.quit()

    def test_headless_with_args(
        self,
        server: str,
    ) -> None:
        assert _uc is not None
        options = _uc.ChromeOptions()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-blink-features=" + "AutomationControlled")
        driver = self._make_uc(options, headless=True)
        try:
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "uc-headless-args",
            )
            assert_detected(result, "uc-headless-args", 0.85)
        finally:
            driver.quit()

    def test_headless_with_subprocess(
        self,
        server: str,
    ) -> None:
        assert _uc is not None
        options = _uc.ChromeOptions()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = self._make_uc(
            options,
            headless=True,
            use_subprocess=True,
        )
        try:
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "uc-headless-subprocess",
            )
            assert_detected(result, "uc-headless-subprocess", 0.85)
        finally:
            driver.quit()

    def test_headless_navigator_spoof(
        self,
        server: str,
    ) -> None:
        assert _uc is not None
        options = _uc.ChromeOptions()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        driver = self._make_uc(options, headless=True)
        try:
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": """
                        Object.defineProperty(
                            navigator,
                            'hardwareConcurrency',
                            { get: () => 8 }
                        );
                        Object.defineProperty(
                            navigator, 'deviceMemory',
                            { get: () => 8 }
                        );
                        window.chrome = {
                            runtime: {
                                sendMessage: () => {},
                                connect: () => {},
                            },
                            csi: () => ({}),
                            loadTimes: () => ({}),
                            app: {isInstalled: false},
                        };
                    """},
            )
            result = get_attestation(driver)
            signals = get_signals(driver)
            print_details(
                result,
                signals,
                "uc-navigator-spoof",
            )
            assert_detected(result, "uc-navigator-spoof", 0.85)
        finally:
            driver.quit()


try:
    from playwright.sync_api import sync_playwright

    has_playwright = True
except ImportError:
    sync_playwright = None
    has_playwright = False


def _pw_get_result(page: Any) -> dict[str, Any]:
    page.goto(BASE_URL)
    page.wait_for_function(
        "window.__attestResult !== undefined",
        timeout=WAIT_TIMEOUT * 1000,
    )
    return page.evaluate("window.__attestResult")


def _pw_get_signals(page: Any) -> dict[str, Any]:
    return page.evaluate("window.__signals") or {}


@pytest.mark.skipif(
    not has_playwright,
    reason="playwright not installed",
)
class TestPlaywrightDetection:
    def test_chromium_headless(
        self,
        server: str,
    ) -> None:
        assert sync_playwright is not None
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            page = browser.new_page()
            try:
                result = _pw_get_result(page)
                signals = _pw_get_signals(page)
                print_details(
                    result,
                    signals,
                    "playwright-chromium-headless",
                )
                assert_detected(
                    result,
                    "playwright-chromium-headless",
                    0.7,
                )
            finally:
                browser.close()

    def test_chromium_headless_antidetect(
        self,
        server: str,
    ) -> None:
        assert sync_playwright is not None
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=" "AutomationControlled",
                    "--window-size=1920,1080",
                ],
            )
            context = browser.new_context(
                viewport={
                    "width": 1920,
                    "height": 1080,
                },
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                locale="en-US",
                timezone_id="America/New_York",
            )
            page = context.new_page()
            try:
                result = _pw_get_result(page)
                signals = _pw_get_signals(page)
                print_details(
                    result,
                    signals,
                    "playwright-chromium-antidetect",
                )
                assert_detected(
                    result,
                    "playwright-chromium-antidetect",
                    0.85,
                )
            finally:
                browser.close()

    def test_chromium_headless_navigator_init(
        self,
        server: str,
    ) -> None:
        assert sync_playwright is not None
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=" "AutomationControlled",
                ],
            )
            context = browser.new_context(
                viewport={
                    "width": 1920,
                    "height": 1080,
                },
            )
            context.add_init_script("""
                Object.defineProperty(
                    navigator, 'webdriver',
                    { get: () => undefined }
                );
                Object.defineProperty(
                    navigator, 'hardwareConcurrency',
                    { get: () => 8 }
                );
                Object.defineProperty(
                    navigator, 'deviceMemory',
                    { get: () => 8 }
                );
                Object.defineProperty(
                    navigator, 'languages',
                    { get: () => ['en-US', 'en'] }
                );
                window.chrome = {
                    runtime: {
                        sendMessage: () => {},
                        connect: () => {},
                    },
                    csi: () => ({}),
                    loadTimes: () => ({}),
                    app: { isInstalled: false },
                };
            """)
            page = context.new_page()
            try:
                result = _pw_get_result(page)
                signals = _pw_get_signals(page)
                print_details(
                    result,
                    signals,
                    "playwright-chromium-init-script",
                )
                assert_detected(
                    result,
                    "playwright-chromium-init-script",
                    0.85,
                )
            finally:
                browser.close()

    def test_chromium_headless_full_stealth(
        self,
        server: str,
    ) -> None:
        assert sync_playwright is not None
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=" "AutomationControlled",
                    "--window-size=1920,1080",
                ],
                ignore_default_args=[
                    "--enable-automation",
                ],
            )
            context = browser.new_context(
                viewport={
                    "width": 1920,
                    "height": 1080,
                },
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                locale="en-US",
                timezone_id="America/New_York",
                color_scheme="dark",
            )
            context.add_init_script("""
                Object.defineProperty(
                    navigator, 'webdriver',
                    { get: () => undefined }
                );
                Object.defineProperty(
                    navigator, 'hardwareConcurrency',
                    { get: () => 8 }
                );
                Object.defineProperty(
                    navigator, 'deviceMemory',
                    { get: () => 8 }
                );
                Object.defineProperty(
                    navigator, 'languages',
                    { get: () => ['en-US', 'en'] }
                );
                Object.defineProperty(
                    navigator, 'platform',
                    { get: () => 'Linux x86_64' }
                );
                Object.defineProperty(
                    navigator, 'vendor',
                    { get: () => 'Google Inc.' }
                );
                Object.defineProperty(
                    navigator, 'maxTouchPoints',
                    { get: () => 0 }
                );
                window.chrome = {
                    runtime: {
                        sendMessage: () => {},
                        connect: () => {},
                    },
                    csi: () => ({}),
                    loadTimes: () => ({}),
                    app: { isInstalled: false },
                };
                const origQuery = window.navigator
                    .permissions.query;
                window.navigator.permissions.query = (
                    params
                ) => (
                    params.name === 'notifications'
                        ? Promise.resolve({
                            state: Notification
                                .permission
                          })
                        : origQuery(params)
                );
            """)
            page = context.new_page()
            try:
                result = _pw_get_result(page)
                signals = _pw_get_signals(page)
                print_details(
                    result,
                    signals,
                    "playwright-chromium-full-stealth",
                )
                assert_detected(
                    result,
                    "playwright-chromium-full-stealth",
                    0.85,
                )
            finally:
                browser.close()

    def test_firefox_headless(
        self,
        server: str,
    ) -> None:
        assert sync_playwright is not None
        with sync_playwright() as p:
            browser = p.firefox.launch(
                headless=True,
            )
            page = browser.new_page()
            try:
                result = _pw_get_result(page)
                signals = _pw_get_signals(page)
                print_details(
                    result,
                    signals,
                    "playwright-firefox-headless",
                )
                assert_detected(
                    result,
                    "playwright-firefox-headless",
                    0.85,
                )
            finally:
                browser.close()

    def test_webkit_headless(
        self,
        server: str,
    ) -> None:
        assert sync_playwright is not None
        with sync_playwright() as p:
            try:
                browser = p.webkit.launch(headless=True)
            except Exception:
                pytest.skip("webkit not available")
                return
            page = browser.new_page()
            try:
                result = _pw_get_result(page)
                signals = _pw_get_signals(page)
                print_details(
                    result,
                    signals,
                    "playwright-webkit-headless",
                )
                assert_detected(
                    result,
                    "playwright-webkit-headless",
                    0.85,
                )
            finally:
                browser.close()


def pytest_terminal_summary(
    terminalreporter: Any,
    exitstatus: int,
) -> None:
    reports = terminalreporter.stats.get("passed", [])
    failed = terminalreporter.stats.get("failed", [])
    skipped = terminalreporter.stats.get("skipped", [])
    total = len(reports) + len(failed) + len(skipped)
    print(f"\n{'=' * 60}")
    print(
        f"Detection Tests: {len(reports)}/{total} passed, "
        f"{len(failed)} failed, {len(skipped)} skipped"
    )
    print(f"{'=' * 60}")
