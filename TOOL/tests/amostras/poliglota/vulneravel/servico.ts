// Amostra vulneravel: TypeScript no servidor (Koa + Prisma).
import Koa from "koa";

const STRIPE_SECRET_KEY: string = "sk_live_51HxExemplo"; // achado: CWE-798

export async function relatorio(ctx: Koa.Context): Promise<void> {
  const mes = ctx.query.mes as string;
  const dados = await prisma.$queryRawUnsafe(`SELECT * FROM vendas WHERE mes = '${mes}'`); // achado: CWE-89
  ctx.body = `<h2>Relatorio de ${mes}</h2>`; // achado: CWE-79
}
