// SPDX-License-Identifier: GPL-3.0-or-later
// Small typed DOM helpers. Every piece of daemon text goes in through
// `textContent`, never as markup.

export const byId = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`The page is missing #${id}`);
  return element as T;
};

type Child = Node | string;

export const el = <K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string | null,
  ...children: Child[]
): HTMLElementTagNameMap[K] => {
  const element = document.createElement(tag);
  if (className !== null) element.className = className;
  element.append(...children);
  return element;
};

export const code = (text: string): HTMLElement => el("code", null, text);

export const button = (
  label: string,
  className: string,
  onClick: () => void,
): HTMLButtonElement => {
  const element = el("button", `button ${className}`, label);
  element.type = "button";
  element.addEventListener("click", onClick);
  return element;
};

/** Says a status change through the polite live region. */
export const announce = (message: string): void => {
  const announcer = byId("announcer");
  // Clearing first makes a repeated message announced again.
  announcer.textContent = "";
  requestAnimationFrame(() => {
    announcer.textContent = message;
  });
};

export const sleep = (milliseconds: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
