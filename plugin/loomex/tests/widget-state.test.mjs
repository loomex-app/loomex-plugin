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
  return { context, form, storage };
}

function lifecycleElement(attributes = {}) {
  const element = fakeElement();
  Object.assign(element, attributes);
  return element;
}

function lifecycleForm() {
  const form = fakeElement();
  const elements = new Map();
  let markup = "";
  Object.defineProperty(form, "innerHTML", {
    get() { return markup; },
    set(value) {
      markup = String(value);
      elements.clear();
      for (const match of markup.matchAll(/<input\b([^>]*)>/g)) {
        const attributes = match[1];
        const id = attributes.match(/\bid="([^"]+)"/)?.[1];
        if (!id) continue;
        elements.set(`#${id}`, lifecycleElement({
          id,
          type: attributes.match(/\btype="([^"]+)"/)?.[1] || "text",
          value: attributes.match(/\bvalue="([^"]*)"/)?.[1] || "",
        }));
      }
      for (const match of markup.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)) {
        const attributes = match[1];
        const id = attributes.match(/\bid="([^"]+)"/)?.[1];
        if (!id) continue;
        elements.set(`#${id}`, lifecycleElement({
          id,
          disabled: /\bdisabled\b/.test(attributes),
          textContent: match[2],
        }));
      }
    },
  });
  form.querySelector = (selector) => {
    if (selector === ".auth-shell") return markup.includes("auth-shell") ? lifecycleElement() : null;
    if (selector === ".auth-otp input") return [...elements.values()].find((element) => element.id?.startsWith("auth-code-")) || null;
    return elements.get(selector) || null;
  };
  form.querySelectorAll = (selector) => {
    const inputs = [...elements.values()].filter((element) => element.type === "text" || element.type === "email" || element.type === "password");
    if (selector === "input") return inputs;
    if (selector === ".auth-otp input") return inputs.filter((element) => element.id?.startsWith("auth-code-"));
    if (selector === "#auth-password, #auth-confirm-password, .auth-otp input") {
      return ["#auth-password", "#auth-confirm-password", ".auth-otp input"].flatMap((part) => form.querySelectorAll(part));
    }
    if (selector.startsWith("#")) return elements.has(selector) ? [elements.get(selector)] : [];
    return [];
  };
  return form;
}

function authLifecycleContext(script, storage, responses) {
  const form = lifecycleForm();
  const main = fakeElement();
  const status = fakeElement();
  const title = fakeElement();
  const summary = fakeElement();
  const events = new Map();
  const intervals = new Set();
  const window = {
    localStorage: storage,
    addEventListener(type, listener) {
      if (!events.has(type)) events.set(type, []);
      events.get(type).push(listener);
    },
    dispatch(type) {
      for (const listener of events.get(type) || []) listener({ type });
    },
    setInterval(callback) {
      intervals.add(callback);
      return callback;
    },
    clearInterval(callback) {
      intervals.delete(callback);
    },
    tick() {
      for (const callback of [...intervals]) callback();
    },
    openai: {
      toolOutput: {
        structuredContent: {
          schemaVersion: "loomex.mcp/v1",
          ok: true,
          tool: "loomex_auth_login",
          data: { authForm: { mode: "login", secure: true, sensitivity: "sensitive" } },
          meta: { requestId: "auth-request", timestampMs: 1 },
        },
      },
      async callTool() {
        const response = responses.shift();
        if (response instanceof Error) throw response;
        return response;
      },
      setWidgetState() {
        throw new Error("secure auth must not write widget state");
      },
    },
  };
  const document = {
    querySelector(selector) {
      return new Map([
        ["#form", form], ["main", main], ["#status", status], ["#title", title], ["#summary", summary],
      ]).get(selector) || null;
    },
    querySelectorAll() { return []; },
  };
  const context = vm.createContext({ window, document });
  vm.runInContext(script, context);
  return { context, form, storage, window };
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

test("secure auth distinguishes OTP failures and exposes expiry/resend cleanup paths", async () => {
  const html = await readFile(
    path.join(repositoryRoot, "crates", "loomex-mcp", "src", "human_input_app.html"),
    "utf8",
  );
  const auth = authContext(scriptFrom(html), new MemoryStorage());
  assert.match(auth.context.authErrorMessage({ code: "OTP_INVALID" }), /invalid/i);
  assert.match(auth.context.authErrorMessage({ code: "OTP_EXPIRED" }), /expired/i);
  assert.match(auth.context.authErrorMessage({ code: "OTP_REPLAYED" }), /already used/i);
  assert.match(auth.context.authErrorMessage({ code: "AUTH_RATE_LIMITED" }), /Too many attempts/i);
  assert.match(html, /scheduleAuthTimers/);
  assert.match(html, /resendAuthCode/);
  assert.match(html, /clearAuthSession/);
  auth.context.clearAuthSession();
  assert.equal(auth.storage.entries.size, 0);
});

test("secure auth renders and validates the backend-declared OTP length with a safe fallback", async () => {
  const html = await readFile(
    path.join(repositoryRoot, "crates", "loomex-mcp", "src", "human_input_app.html"),
    "utf8",
  );
  const auth = authLifecycleContext(scriptFrom(html), new MemoryStorage(), []);
  auth.context.renderAuth({
    authForm: { mode: "otp" },
    challenge: { challengeId: "challenge-8", email: "new@example.com", status: "pending", codeLength: 8, expiresAt: "2099-01-01T00:00:00Z" },
  });
  assert.equal(auth.form.querySelectorAll(".auth-otp input").length, 8);
  auth.form.querySelectorAll(".auth-otp input").forEach((input, index) => { input.value = String(index + 1); });
  await auth.form.listeners.get("submit")({ preventDefault() {} });

  auth.context.renderAuth({
    authForm: { mode: "otp" },
    challenge: { challengeId: "challenge-fallback", email: "new@example.com", status: "pending", codeLength: 99, expiresAt: "2099-01-01T00:00:00Z" },
  });
  assert.equal(auth.form.querySelectorAll(".auth-otp input").length, 6);
});

test("secure auth lifecycle clears secrets across submit, rejection, expiry, cancel, logout, resend, and mode changes", async () => {
  const html = await readFile(
    path.join(repositoryRoot, "crates", "loomex-mcp", "src", "human_input_app.html"),
    "utf8",
  );
  const success = {
    structuredContent: {
      ok: true,
      data: { authForm: { mode: "login", secure: true, sensitivity: "sensitive" }, authenticated: true },
    },
  };
  const rejected = {
    structuredContent: {
      ok: false,
      error: { code: "AUTHENTICATION_FAILED", message: "Invalid email or password" },
    },
  };
  const resent = {
    structuredContent: {
      ok: true,
      data: {
        authForm: { mode: "reset", secure: true, sensitivity: "sensitive" },
        pending: true,
        challenge: {
          challengeId: "reset-2",
          email: "user@example.com",
          status: "pending",
          expiresAt: "2099-01-01T00:00:00Z",
          resendAvailableAt: null,
        },
      },
    },
  };
  const auth = authLifecycleContext(scriptFrom(html), new MemoryStorage(), [success, rejected, resent]);
  const submit = () => auth.form.listeners.get("submit")({ preventDefault() {} });
  const fillPassword = () => {
    auth.form.querySelector("#auth-password").value = "Password1!";
    const confirm = auth.form.querySelector("#auth-confirm-password");
    if (confirm) confirm.value = "Password1!";
  };

  auth.form.querySelector("#auth-email").value = "user@example.com";
  auth.form.querySelector("#auth-password").value = "Password1!";
  await submit();
  assert.equal(auth.form.querySelector("#auth-password").value, "");
  assert.equal(auth.storage.entries.size, 0);

  auth.form.querySelector("#auth-email").value = "user@example.com";
  auth.form.querySelector("#auth-password").value = "Password1!";
  await submit();
  assert.equal(auth.form.querySelector("#auth-password").value, "");
  assert.equal(auth.storage.entries.size, 0);

  auth.context.renderAuth({
    authForm: { mode: "otp" },
    challenge: {
      challengeId: "challenge-1",
      email: "new@example.com",
      status: "pending",
      expiresAt: "2000-01-01T00:00:00Z",
      resendAvailableAt: null,
    },
  });
  const expiredOtp = auth.form.querySelectorAll(".auth-otp input");
  expiredOtp[0].value = "1";
  auth.window.tick();
  assert.equal(expiredOtp[0].value, "");

  auth.context.renderAuth({
    authForm: { mode: "reset" },
    challenge: { challengeId: "reset-1", email: "user@example.com", status: "pending", expiresAt: "2099-01-01T00:00:00Z" },
  });
  fillPassword();
  const cancelPassword = auth.form.querySelector("#auth-password");
  const cancelConfirm = auth.form.querySelector("#auth-confirm-password");
  const cancelOtp = auth.form.querySelectorAll(".auth-otp input")[0];
  cancelOtp.value = "1";
  auth.form.querySelector("#auth-back").listeners.get("click")();
  assert.equal(cancelPassword.value, "");
  assert.equal(cancelConfirm.value, "");
  assert.equal(cancelOtp.value, "");

  auth.context.renderAuth({
    authForm: { mode: "reset" },
    challenge: { challengeId: "reset-1", email: "user@example.com", status: "pending", expiresAt: "2099-01-01T00:00:00Z" },
  });
  fillPassword();
  const logoutPassword = auth.form.querySelector("#auth-password");
  const logoutOtp = auth.form.querySelectorAll(".auth-otp input")[0];
  logoutOtp.value = "2";
  auth.window.dispatch("loomex:auth-logout");
  assert.equal(logoutPassword.value, "");
  assert.equal(logoutOtp.value, "");

  auth.context.renderAuth({
    authForm: { mode: "reset" },
    challenge: { challengeId: "reset-1", email: "user@example.com", status: "pending", expiresAt: "2099-01-01T00:00:00Z", resendAvailableAt: null },
  });
  fillPassword();
  const resendPassword = auth.form.querySelector("#auth-password");
  const resendOtp = auth.form.querySelectorAll(".auth-otp input")[0];
  resendOtp.value = "3";
  auth.form.querySelector("#auth-resend").listeners.get("click")();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(resendPassword.value, "");
  assert.equal(resendOtp.value, "");
  assert.equal(auth.storage.entries.size, 0);

  auth.context.renderAuth({ authForm: { mode: "login" } });
  auth.form.querySelector("#auth-password").value = "Password1!";
  const modePassword = auth.form.querySelector("#auth-password");
  auth.form.querySelector("#auth-register-tab").listeners.get("click")();
  assert.equal(modePassword.value, "");
  assert.equal(auth.storage.entries.size, 0);
});
