// Callers: `CodeBlock` and `DiffViewer`.
// API: `tokenize` emits text spans only. No HTML parsing.
// Schema: none. Untrusted text stays a text node.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. CodeBlock and DiffViewer build DOM text nodes and spans only.

const KEYWORDS = new Set([
  "fn",
  "let",
  "const",
  "mut",
  "pub",
  "struct",
  "enum",
  "impl",
  "use",
  "return",
  "if",
  "else",
  "match",
  "async",
  "await",
  "true",
  "false",
  "null",
  "function",
  "class",
  "import",
  "export",
]);

export type Token = { kind: "kw" | "str" | "num" | "cmt" | "plain"; text: string };

export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < source.length) {
    const rest = source.slice(index);
    const comment = rest.match(/^\/\/[^\n]*/);
    if (comment?.[0]) {
      tokens.push({ kind: "cmt", text: comment[0] });
      index += comment[0].length;
      continue;
    }
    const string = rest.match(/^"(?:\\.|[^"\\])*"|^'(?:\\.|[^'\\])*'/);
    if (string?.[0]) {
      tokens.push({ kind: "str", text: string[0] });
      index += string[0].length;
      continue;
    }
    const number = rest.match(/^\d+(?:\.\d+)?/);
    if (number?.[0]) {
      tokens.push({ kind: "num", text: number[0] });
      index += number[0].length;
      continue;
    }
    const word = rest.match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (word?.[0]) {
      tokens.push({ kind: KEYWORDS.has(word[0]) ? "kw" : "plain", text: word[0] });
      index += word[0].length;
      continue;
    }
    tokens.push({ kind: "plain", text: rest[0] ?? "" });
    index += 1;
  }
  return tokens;
}
