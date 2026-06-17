# Server Detail Redesign

Mockup funcional en React para redisenar la pantalla de detalle de servidor con estilo empresarial tipo Grafana, Proxmox, VMware vCenter y Azure Portal.

## Entregables

- `ServerDetailPage.jsx`: JSX completo con datos mock y componentes reutilizables.
- `tailwind.css`: entrada TailwindCSS con fuente Inter.
- `tailwind.config.js`: configuracion de Tailwind para colores, dark mode y animaciones.

## Componentes incluidos

- `ServerDetailPage`
- `Header`
- `KpiCard`
- `InfoCard`
- `DiskCard`
- `CredentialsTable`
- `CredentialModal`
- `TerminalPanel`
- `MetricChart`
- `EventsTable`
- Componentes base tipo shadcn: `Card`, `Button`, `Badge`, `Progress`, `SectionHeader`, `Skeleton`

## Layout

La pantalla usa una grilla responsive de 12 columnas con separacion de 16px. En desktop se muestran secciones densas y alineadas; en tablet/mobile cae a una columna sin perder jerarquia.

## Integracion sugerida

Dependencias:

```bash
npm install lucide-react
npm install -D tailwindcss postcss autoprefixer
```

Tailwind debe procesar:

```js
content: ["./src/**/*.{js,jsx,ts,tsx}"]
```

El mockup usa datos locales en `serverMock`. Para produccion, reemplazar esos datos por props o por una llamada API.
