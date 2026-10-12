// Datos de la petición que se guardan en cada evento de auditoría.
export const contextOf = (req) => ({
  ip: req.ip,
  path: req.originalUrl.split('?')[0],
  requestId: req.requestId,
});

export const bearerTokenOf = (req) => {
  const [scheme, token] = (req.get('authorization') ?? '').split(' ');
  return scheme === 'Bearer' && token ? token : null;
};

export const sourceAddressOf = (req) => (req.socket.remoteAddress ?? '').replace(/^::ffff:/, '');
