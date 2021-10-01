const jwt = require("jsonwebtoken");

function extractTokenFromHeaders(req) {
  // verificar se o cabeçalho Authorization existe
  if (!req.headers.authorization) {
    throw new Error("Faltando o cabeçalho Authorization");
  }

  return req.headers.authorization.split(" ")[1];
}

module.exports = (req, res, next) => {
  // Extrai o token do cabeçalho da requisição
  const token = extractTokenFromHeaders(req);

  // Verifica se o token é válido
  jwt.verify(token, process.env.TOKEN_SIGN_SECRET, (err, decoded) => {
    if (err) {
      console.error(err.message);
      return res
        .status(401)
        .json({ msg: "Acesso negado", reason: err.message });
    }

    req.user = decoded;
    return next();
  });
};
