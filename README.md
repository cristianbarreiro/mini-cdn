# mini-cdn

Mini CDN Edge (plantilla)
========================

Este proyecto es una implementación simple de un CDN (Content Delivery Network) en Go, pensado como plantilla didáctica y base para experimentos de edge caching.

## Características principales

- Reverse proxy hacia un servidor de origen
- Cache LRU en memoria con TTL configurable
- Respeta directivas básicas de Cache-Control
- Clave de cache sensible a `Vary: Accept-Encoding`
- Endpoint de purga (`PURGE`) protegido por token
- Rate limiting básico por IP
- Timeouts y logging

## Uso rápido

1. Instala Go (>=1.18)
2. Clona este repositorio
3. Ejecuta el servidor:

```bash
go run .
```

Por defecto escucha en `:3000` y hace proxy a `http://127.0.0.1:8080`.

## Endpoints

- `/` — Proxy y cache de contenido estático
- `/__purge` — Purga de cache (requiere header `X-Purge-Token`)

## Configuración

Edita el struct `Config` en `main.go` para ajustar:
- Puerto de escucha
- URL de origen
- Tamaño y cantidad máxima de entradas en cache
- TTL por defecto
- Token de purga
- Rate limit por IP

## TODO / Roadmap

- [ ] Usar `context.WithTimeout` real (import "context")
- [ ] Implementar índice path->keys para `PurgeExact` / `PurgePrefix`
- [ ] Soportar revalidación con ETag/If-None-Match (cache con stale-while-revalidate)
- [ ] Compresión (gzip/br) o respetar la del origin
- [ ] Métricas Prometheus: hit_ratio, latency p95, 5xx, bytes
- [ ] Persistir cache (opcional) o usar Redis para cache compartido entre nodos

## Licencia

MIT
