"""Measure public IS Manager pages at real Chromium tab zoom on a disposable installation."""
import argparse
import json
import os
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright


SIZES = [(320, 640), (390, 844), (768, 1024), (1280, 800), (1366, 768),
         (1440, 900), (1512, 982), (1920, 1080)]
PATHS = ('/', '/transcription/', '/redaction/', '/passwords/', '/threats/', '/login')
SET_ZOOM = '''async zoom => {
    const [tab] = await chrome.tabs.query({active: true});
    await chrome.tabs.setZoom(tab.id, zoom);
    return await chrome.tabs.getZoom(tab.id);
}'''
MEASURE = '''() => {
    const nav = document.querySelector('.module-nav');
    const bounds = nav.getBoundingClientRect();
    const clipped = [...nav.querySelectorAll('a')].some(a => {
        const rect = a.getBoundingClientRect();
        return rect.right > bounds.right + 1 || rect.left < bounds.left - 1;
    });
    return {width: innerWidth, overflow: document.documentElement.scrollWidth - innerWidth, clipped};
}'''


def run(origin, axe):
    failures = []
    with tempfile.TemporaryDirectory() as work, sync_playwright() as playwright:
        extension = Path(work, 'zoom')
        extension.mkdir()
        (extension / 'manifest.json').write_text(json.dumps({
            'manifest_version': 3, 'name': 'Local zoom test', 'version': '1.0',
            'permissions': ['tabs'], 'background': {'service_worker': 'zoom.js'},
        }))
        (extension / 'zoom.js').write_text('chrome.runtime.onInstalled.addListener(() => {});')
        browser = playwright.chromium.launch_persistent_context(
            Path(work, 'profile'), executable_path=os.getenv('CHROMIUM_PATH'), channel='chromium',
            args=[f'--load-extension={extension}', f'--disable-extensions-except={extension}'],
            bypass_csp=bool(axe),
        )
        worker = browser.service_workers[0] if browser.service_workers else browser.wait_for_event('serviceworker')
        page = browser.pages[0]
        page.on('pageerror', lambda exc: failures.append(str(exc)))
        page.on('console', lambda msg: failures.append(msg.text) if msg.type == 'error' else None)
        page.on('response', lambda r: failures.append(f'{r.status} {r.url}') if r.status >= 400 else None)
        page.on('requestfailed', lambda r: failures.append(f'{r.failure} {r.url}') if r.failure != 'net::ERR_ABORTED' else None)
        page.goto(origin)
        for width, height in SIZES:
            page.set_viewport_size({'width': width, 'height': height})
            for zoom in (1, 1.25, 1.5):
                assert worker.evaluate(SET_ZOOM, zoom) == zoom
                for path in PATHS:
                    page.goto(origin + path)
                    page.evaluate('document.fonts.ready.then(() => true)')
                    measured = page.evaluate(MEASURE)
                    if measured['overflow'] > 1 or measured['clipped']:
                        failures.append(f'{path} {width}×{height} zoom={zoom} {measured}')
        if axe:
            worker.evaluate(SET_ZOOM, 1)
            script = axe.read_text()
            for width, height in ((1366, 768), (390, 844)):
                page.set_viewport_size({'width': width, 'height': height})
                for theme in ('glass', 'light', 'dark'):
                    page.evaluate("t => localStorage.setItem('ismanager-theme', t)", theme)
                    for path in PATHS:
                        page.goto(origin + path)
                        page.evaluate(script)
                        ids = page.evaluate('''async () => (await axe.run(document, {runOnly: {type: 'tag',
                            values: ['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']}})).violations.map(v => v.id)''')
                        if ids:
                            failures.append(f'{path} {theme} {ids}')
        browser.close()
    assert not failures, '\n'.join(failures)
    print(f'{len(SIZES) * 3 * len(PATHS)} layout checks passed.' + (' 36 axe checks passed.' if axe else ''))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('origin', help='URL of a disposable installation')
    parser.add_argument('--axe', type=Path, help='Optional local axe-core distribution, axe.min.js')
    args = parser.parse_args()
    run(args.origin.rstrip('/'), args.axe)
