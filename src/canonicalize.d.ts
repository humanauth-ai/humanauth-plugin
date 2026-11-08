// `canonicalize` (RFC 8785 JCS) ships no type declarations. It is a CommonJS
// module whose export is the serializer function itself.
declare module "canonicalize" {
  function canonicalize(input: unknown): string | undefined;
  export = canonicalize;
}
