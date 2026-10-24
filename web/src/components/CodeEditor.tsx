import { useEffect, useRef } from "react";
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { StreamLanguage, HighlightStyle, syntaxHighlighting, bracketMatching, indentOnInput } from "@codemirror/language";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { powerShell } from "@codemirror/legacy-modes/mode/powershell";
import { tags } from "@lezer/highlight";

const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content ?? "";

// Colors come from the app's tokens so the editor follows the theme.
const highlight = HighlightStyle.define([
  { tag: [tags.keyword, tags.controlKeyword, tags.operatorKeyword], color: "var(--accent)" },
  { tag: [tags.string, tags.special(tags.string)], color: "var(--ok)" },
  { tag: [tags.comment, tags.lineComment, tags.blockComment], color: "var(--text-faint)", fontStyle: "italic" },
  { tag: [tags.variableName, tags.special(tags.variableName)], color: "var(--info)" },
  { tag: [tags.number, tags.bool, tags.atom], color: "var(--warn)" },
  { tag: [tags.function(tags.variableName), tags.definition(tags.variableName)], color: "var(--text)" },
  { tag: tags.operator, color: "var(--text-muted)" },
]);

const theme = EditorView.theme({
  "&": { color: "var(--text)", backgroundColor: "var(--surface)", fontSize: "13px", height: "100%" },
  ".cm-scroller": { fontFamily: 'var(--font-mono, "Cascadia Mono", Consolas, monospace)', lineHeight: "1.55" },
  ".cm-content": { caretColor: "var(--accent)" },
  ".cm-gutters": { backgroundColor: "var(--surface-2)", color: "var(--text-faint)", border: "none", borderRight: "1px solid var(--border)" },
  ".cm-activeLine": { backgroundColor: "var(--accent-soft)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--accent-soft)", color: "var(--text)" },
  "&.cm-focused": { outline: "none" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "rgb(109 139 255 / 0.28)" },
  ".cm-panels": { backgroundColor: "var(--surface-2)", color: "var(--text)", borderColor: "var(--border)" },
  ".cm-textfield": { backgroundColor: "var(--surface)", color: "var(--text)", border: "1px solid var(--border)" },
  ".cm-button": { backgroundImage: "none", backgroundColor: "var(--surface-3)", color: "var(--text)", border: "1px solid var(--border)" },
});

/** PowerShell code editor. Uncontrolled after mount; reports every change. */
export function CodeEditor({ value, onChange, readOnly, minHeight = 360 }: { value: string; onChange?: (v: string) => void; readOnly?: boolean; minHeight?: number }) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const change = useRef(onChange);
  change.current = onChange;

  useEffect(() => {
    if (!host.current) return;
    view.current = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: value,
        extensions: [
          EditorView.cspNonce.of(nonce),
          lineNumbers(),
          highlightActiveLineGutter(),
          highlightActiveLine(),
          drawSelection(),
          history(),
          indentOnInput(),
          bracketMatching(),
          highlightSelectionMatches(),
          StreamLanguage.define(powerShell),
          syntaxHighlighting(highlight),
          keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap, indentWithTab]),
          EditorState.readOnly.of(!!readOnly),
          EditorView.editable.of(!readOnly),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) change.current?.(u.state.doc.toString());
          }),
          theme,
        ],
      }),
    });
    return () => {
      view.current?.destroy();
      view.current = null;
    };
    // The editor owns its document after mount; `value` seeds it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readOnly]);

  // Replace the document only when a different script is loaded.
  useEffect(() => {
    const v = view.current;
    if (v && v.state.doc.toString() !== value) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } });
  }, [value]);

  return <div ref={host} className="overflow-hidden rounded-md border border-border" style={{ minHeight }} />;
}
