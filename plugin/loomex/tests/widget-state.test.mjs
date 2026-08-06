import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(pluginRoot, "..", "..");

function scriptFrom(html) {
  const match = html.match(/<script>([\s\S]*)<\/script>/);
  assert.ok(match, "widget HTML must contain an inline script");
  return match[1];
}

class MemoryStorage {
  constructor(entries = []) {
    this.entries = new Map(entries);
  }

  getItem(key) {
    return this.entries.has(key) ? this.entries.get(key) : null;
  }

  setItem(key, value) {
    this.entries.set(key, String(value));
  }
}

class FakeClassList {
  constructor() {
    this.values = new Set();
  }

  add(value) {
    this.values.add(value);
  }

  remove(value) {
    this.values.delete(value);
  }

  toggle(value, force) {
    const enabled = force === undefined ? !this.values.has(value) : Boolean(force);
    if (enabled) this.values.add(value);
    else this.values.delete(value);
    return enabled;
  }

  contains(value) {
    return this.values.has(value);
  }
}

function fakeElement() {
  return {
    value: "",
    textContent: "",
    innerHTML: "",
    className: "",
    checked: false,
    disabled: false,
    hidden: false,
    style: {},
    classList: new FakeClassList(),
    listeners: new Map(),
    addEventListener(type, listener) {
      this.listeners.set(type, listener);
    },
    querySelector() {
      return null;
    },
    querySelectorAll() {
      return [];
    },
    replaceChildren() {},
    requestSubmit() {},
  };
}

function listContext(script, storage, requestId) {
  const elements = new Map(
    ["#title", "#summary", "#state", "#toolbar", "#search", "#count", "#table", "#head", "#body"]
      .map((selector) => [selector, fakeElement()]),
  );
  const setWidgetStateCalls = [];
  const window = {
    localStorage: storage,
    addEventListener() {},
    openai: {
      toolOutput: {
        structuredContent: {
          schemaVersion: "loomex.mcp/v1",
          ok: true,
          tool: "loomex_workflow_list",
          data: { workflows: [{ id: "workflow-1", name: "Workflow" }] },
          meta: { requestId, timestampMs: 1 },
        },
      },
      setWidgetState(state) {
        setWidgetStateCalls.push(state);
      },
    },
  };
  const context = vm.createContext({
    window,
    document: {
      querySelector(selector) {
        return elements.get(selector) || fakeElement();
      },
    },
  });
  vm.runInContext(script, context);
  return { context, setWidgetStateCalls };
}

function humanContext(script, storage, requestId) {
  const form = fakeElement();
  const main = fakeElement();
  const status = fakeElement();
  const title = fakeElement();
  const summary = fakeElement();
  const otherInput = fakeElement();
  const otherOption = fakeElement();
  otherOption.value = "other";
  otherOption.checked = true;

  form.querySelector = (selector) => selector === "#otherText-0" ? otherInput : null;
  form.querySelectorAll = (selector) => selector === 'input[name="value-0"]'
    ? [otherOption]
    : [];

  const document = {
    querySelector(selector) {
      if (selector === "#form") return form;
      if (selector === "main") return main;
      if (selector === "#status") return status;
      if (selector === "#title") return title;
      if (selector === "#summary") return summary;
      if (selector === "#otherText-0") return otherInput;
      return null;
    },
    querySelectorAll(selector) {
      return selector === 'input[name="value-0"]:checked' ? [otherOption] : [];
    },
  };

  const setWidgetStateCalls = [];
  const window = {
    localStorage: storage,
    addEventListener() {},
    openai: {
      toolOutput: {
        structuredContent: {
          schemaVersion: "loomex.mcp/v1",
          ok: true,
          tool: "loomex_human_open",
          data: {
            humanRequest: {
              id: "human-1",
              status: "pending",
              inputSpec: {
                inputType: "radio",
                question: "Choose",
                options: ["A"],
                allowOther: true,
              },
            },
          },
          meta: { requestId, timestampMs: 1 },
        },
      },
      setWidgetState(state) {
        setWidgetStateCalls.push(state);
      },
    },
  };
  const context = vm.createContext({ window, document });
  vm.runInContext(script, context);
  return { form, otherInput, setWidgetStateCalls };
}

function authContext(script, storage) {
  const form = fakeElement();
  const main = fakeElement();
  const status = fakeElement();
  const elements = new Map([["#form", form], ["main", main], ["#status", status]]);
  const window = {
    localStorage: storage,
    addEventListener() {},
    openai: {
      toolOutput: {
        structuredContent: {
          schemaVersion: "loomex.mcp/v1",
          ok: true,
          tool: "loomex_auth_login",
          data: {
            authForm: {
              mode: "login",
              secure: true,
              sensitivity: "sensitive",
            },
          },
          meta: { requestId: "auth-request", timestampMs: 1 },
        },
      },
      setWidgetState() {
        throw new Error("secure auth must not write widget state");
      },
    },
  };
  const context = vm.createContext({
    window,
    document: {
      querySelector(selector) {
        return elements.get(selector) || fakeElement();
      },
    },
  });
  vm.runInContext(script, context);
  return { form, storage };
}

test("workflow action state survives remounts but does not leak to another tool-result scope", async () => {
  const html = await readFile(
    path.join(repositoryRoot, "crates", "loomex-mcp", "src", "list_table_app.html"),
    "utf8",
  );
  const script = scriptFrom(html);
  const storage = new MemoryStorage();

  const first = listContext(script, storage, "chat-a");
  first.context.saveActionState("loomex_workflow_run", "workflow-1", "Started");
  assert.equal(
    JSON.parse(storage.getItem("loomex-list-action-state:chat-a"))[
      "loomex_workflow_run:workflow-1"
    ].label,
    "Started",
  );

  const reopened = listContext(script, storage, "chat-a");
  assert.equal(
    reopened.context.actionState("loomex_workflow_run", "workflow-1").label,
    "Started",
  );

  const differentChat = listContext(script, storage, "chat-b");
  assert.equal(differentChat.context.actionState("loomex_workflow_run", "workflow-1"), null);
  assert.equal(storage.getItem("loomex-list-action-state"), null);
});

test("human-input drafts restore only in the same tool-result scope without stealing Other focus", async () => {
  const html = await readFile(
    path.join(repositoryRoot, "crates", "loomex-mcp", "src", "human_input_app.html"),
    "utf8",
  );
  const script = scriptFrom(html);
  const storage = new MemoryStorage();

  const first = humanContext(script, storage, "chat-a");
  first.otherInput.value = "custom answer";
  first.otherInput.listeners.get("input")();

  assert.equal(first.setWidgetStateCalls.length, 0);
  const persisted = JSON.parse(storage.getItem("loomex-human-input:chat-a:human-1"));
  assert.equal(persisted.answers[0].otherText, "custom answer");

  const reopened = humanContext(script, storage, "chat-a");
  assert.equal(reopened.otherInput.value, "custom answer");

  persisted.submissionSucceeded = true;
  persisted.showingReview = true;
  storage.setItem("loomex-human-input:chat-a:human-1", JSON.stringify(persisted));
  const submitted = humanContext(script, storage, "chat-a");
  assert.equal(submitted.form.classList.contains("submitted"), true);

  const differentChat = humanContext(script, storage, "chat-b");
  assert.equal(differentChat.otherInput.value, "");
  assert.equal(differentChat.form.classList.contains("submitted"), false);
});

test("secure auth form does not persist widget or reload state", async () => {
  const html = await readFile(
    path.join(repositoryRoot, "crates", "loomex-mcp", "src", "human_input_app.html"),
    "utf8",
  );
  const storage = new MemoryStorage();
  const auth = authContext(scriptFrom(html), storage);
  assert.match(auth.form.innerHTML, /auth-shell/);
  assert.equal(storage.entries.size, 0);
});
