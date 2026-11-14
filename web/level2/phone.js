// Renders the simulated phone's messages. textContent only: message bodies are data.
export function renderInbox(container, messages) {
  container.replaceChildren();
  if (messages.length === 0) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No messages yet.";
    container.appendChild(p);
    return;
  }
  for (const m of messages) {
    const box = document.createElement("div");
    box.className = "sms";
    const meta = document.createElement("small");
    meta.textContent = `to ${m.number}`;
    const body = document.createElement("span");
    body.textContent = m.body;
    box.append(meta, body);
    container.appendChild(box);
  }
}
