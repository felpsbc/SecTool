// Amostra vulneravel: React/TSX.
import React from "react";

export function Comentario(): JSX.Element {
  const texto: string = new URLSearchParams(window.location.search).get("c")!;
  return <div dangerouslySetInnerHTML={{ __html: texto }} />; // achado: CWE-79
}
