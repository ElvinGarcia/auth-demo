// Renders the simulated mailbox. textContent only: message fields are data, never HTML.
export function renderMailbox(container, addresses, messages) {
  container.replaceChildren();
  const hint = document.createElement("p");
  hint.className = "muted";
  hint.style.fontSize = "0.8rem";
  hint.textContent = addresses.length
    ? `Open mailboxes: ${addresses.join(", ")}`
    : "No mailbox is open in this browser.";
  container.appendChild(hint);
  for (const m of messages) {
    const box = document.createElement("div");
    box.className = "mail";
    const to = document.createElement("small");
    to.textContent = `to ${m.address}`;
    const subject = document.createElement("div");
    subject.className = "subject";
    subject.textContent = m.subject;
    const text = document.createElement("div");
    text.className = "text";
    text.textContent = m.body;
    box.append(to, subject, text);
    container.appendChild(box);
  }
}
