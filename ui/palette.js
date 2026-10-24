"use strict";
// Command palette for a text box: type "/" to see the commands with a line
// of help each, keep typing to filter, ↑/↓ to move, Tab or Enter to fill in
// the command, Esc to close; a click also picks. One copy, shared by the
// desktop app and Bulge Remote (each app's build copies it into its dist/).
//
//   BulgePalette.attach(textarea, () => [{ name: "stop", summary: "…" }, …])
//
// Enter only picks while the list is open; otherwise the app's own Enter
// handling (send) runs. IME composition (e.g. picking a Chinese candidate)
// is never taken as a pick.
(function () {
  const STYLE = `
.bulge-palette { position: absolute; left: 0; right: 0; bottom: calc(100% + 8px); z-index: 50;
  max-height: 260px; overflow-y: auto; margin: 0; padding: 6px; list-style: none;
  background: var(--palette-bg, var(--surface, #fff)); color: var(--text, #1c1f24);
  border: 1px solid var(--line, #dfe2e7); border-radius: var(--palette-radius, 10px);
  box-shadow: var(--palette-shadow, 0 6px 24px rgba(0,0,0,.18));
  backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); }
.bulge-palette[hidden] { display: none; }
.bulge-palette li { position: relative; display: flex; gap: 14px; align-items: baseline; padding: 8px 12px; border-radius: 8px; cursor: pointer; }
.bulge-palette li.active { background: var(--palette-active-bg, var(--accent, #2f6fde)); color: var(--palette-active-ink, var(--accent-text, #fff)); }
.bulge-palette li.active::before { content: ""; position: absolute; left: 0; top: 8px; bottom: 8px; width: 2px; border-radius: 2px; background: var(--palette-marker, transparent); }
.bulge-palette .cmd { font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, monospace); font-weight: 600; font-size: .92em; min-width: 7.5em; }
.bulge-palette li.active .cmd { color: var(--palette-active-cmd, inherit); }
.bulge-palette .help { opacity: .75; font-size: .92em; }
.bulge-palette li.active .help { opacity: 1; }`;

  function injectStyle() {
    if (document.getElementById("bulge-palette-style")) return;
    const style = document.createElement("style");
    style.id = "bulge-palette-style";
    style.textContent = STYLE;
    document.head.append(style);
  }

  function attach(input, commands) {
    injectStyle();
    const host = input.parentElement;
    if (getComputedStyle(host).position === "static") host.style.position = "relative";
    const list = document.createElement("ul");
    list.className = "bulge-palette";
    list.hidden = true;
    list.setAttribute("role", "listbox");
    host.append(list);
    let shown = [];
    let active = 0;

    function query() {
      const value = input.value;
      // Only while the box holds a single "/word" (no spaces yet).
      return /^\/[\w-]*$/.test(value) ? value.slice(1).toLowerCase() : null;
    }

    function render() {
      list.replaceChildren();
      shown.forEach((command, i) => {
        const item = document.createElement("li");
        item.setAttribute("role", "option");
        if (i === active) item.className = "active";
        const name = document.createElement("span");
        name.className = "cmd";
        name.textContent = "/" + command.name;
        const help = document.createElement("span");
        help.className = "help";
        help.textContent = command.summary;
        item.append(name, help);
        item.addEventListener("mousedown", (event) => {
          event.preventDefault();
          pick(i);
        });
        list.append(item);
      });
      list.hidden = shown.length === 0;
      const current = list.children[active];
      if (current) current.scrollIntoView({ block: "nearest" });
    }

    function update() {
      const q = query();
      shown = q === null ? [] : (commands() || []).filter((c) => c.name.startsWith(q));
      active = Math.min(active, Math.max(shown.length - 1, 0));
      render();
    }

    function pick(i) {
      const command = shown[i];
      if (!command) return;
      input.value = "/" + command.name + " ";
      shown = [];
      render();
      input.focus();
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }

    input.addEventListener("input", update);
    input.addEventListener("blur", () => { shown = []; render(); });
    // Capture phase: runs before the app's own Enter-to-send handler.
    input.addEventListener("keydown", (event) => {
      if (list.hidden || event.isComposing || event.keyCode === 229) return;
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        const step = event.key === "ArrowDown" ? 1 : -1;
        active = (active + step + shown.length) % shown.length;
        render();
      } else if (event.key === "Enter" && !event.shiftKey && shown[active] && input.value === "/" + shown[active].name) {
        // Already complete: let Enter send it.
        shown = [];
        render();
        return;
      } else if (event.key === "Tab" || (event.key === "Enter" && !event.shiftKey)) {
        pick(active);
      } else if (event.key === "Escape") {
        shown = [];
        render();
      } else {
        return;
      }
      event.preventDefault();
      event.stopImmediatePropagation();
    }, true);
    return { refresh: update };
  }

  window.BulgePalette = { attach };
})();
