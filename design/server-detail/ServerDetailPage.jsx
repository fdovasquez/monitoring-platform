import React, { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CircleDot,
  Clock3,
  Copy,
  Cpu,
  Download,
  Edit3,
  HardDrive,
  MemoryStick,
  Monitor,
  Network,
  Play,
  Plus,
  RefreshCcw,
  ShieldCheck,
  Terminal,
  Trash2,
  X,
  Zap,
} from "lucide-react";

const serverMock = {
  name: "eidb.hospitalcurico.cl",
  hostname: "eidb.hospitalcurico.cl",
  ip: "192.168.0.107",
  os: "Oracle Linux 8",
  kernel: "5.15.0-203.146.5.el8uek.x86_64",
  version: "8.10",
  status: "Online",
  environment: "Produccion",
  group: "Base de datos",
  owner: "Equipo DBA",
  createdAt: "2026-06-17 10:14",
  lastCheck: "Hace 42 segundos",
  agentStatus: "Activo",
  kpis: {
    cpu: 41,
    ram: 68,
    disk: 82,
    uptime: "21d 04h",
    security: 92,
  },
  disks: [
    { name: "/", capacity: "120 GB", used: "98.4 GB", free: "21.6 GB", percent: 82 },
    { name: "/u01", capacity: "500 GB", used: "203 GB", free: "297 GB", percent: 40 },
    { name: "/backup", capacity: "2 TB", used: "1.4 TB", free: "600 GB", percent: 70 },
  ],
  credentials: [
    { id: 1, user: "oracle", port: 22, lastValidation: "Hace 5 min", status: "Valida" },
    { id: 2, user: "monitor", port: 22, lastValidation: "Hace 1 h", status: "Valida" },
  ],
  charts: {
    cpu: [25, 28, 32, 30, 35, 42, 39, 41, 43, 40, 41],
    ram: [56, 58, 61, 63, 65, 66, 67, 67, 68, 68, 68],
    disk: [79, 79, 80, 80, 81, 81, 81, 82, 82, 82, 82],
    network: [12, 18, 28, 21, 34, 30, 42, 38, 45, 33, 28],
  },
  events: [
    { date: "2026-06-17 11:42", type: "Agente", severity: "Info", message: "Metricas recibidas correctamente." },
    { date: "2026-06-17 11:31", type: "Disco", severity: "Warning", message: "Uso de disco principal supera 80%." },
    { date: "2026-06-17 10:58", type: "SSH", severity: "Info", message: "Conexion validada para usuario oracle." },
    { date: "2026-06-17 09:14", type: "Sistema", severity: "Critical", message: "Pico de memoria superior a 90% durante 2 minutos." },
  ],
};

function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}

function utilizationTone(value) {
  if (value >= 90) return "danger";
  if (value >= 80) return "orange";
  if (value >= 65) return "warning";
  return "success";
}

const toneClass = {
  success: {
    text: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500",
    soft: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-900",
  },
  warning: {
    text: "text-amber-600 dark:text-amber-400",
    bg: "bg-amber-500",
    soft: "bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-900",
  },
  orange: {
    text: "text-orange-600 dark:text-orange-400",
    bg: "bg-orange-500",
    soft: "bg-orange-50 text-orange-700 ring-orange-200 dark:bg-orange-950/40 dark:text-orange-300 dark:ring-orange-900",
  },
  danger: {
    text: "text-red-600 dark:text-red-400",
    bg: "bg-red-500",
    soft: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-900",
  },
  primary: {
    text: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-600",
    soft: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-950/40 dark:text-blue-300 dark:ring-blue-900",
  },
  neutral: {
    text: "text-slate-600 dark:text-slate-300",
    bg: "bg-slate-500",
    soft: "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800",
  },
};

const strokeClass = {
  success: "stroke-emerald-600 dark:stroke-emerald-400",
  warning: "stroke-amber-600 dark:stroke-amber-400",
  orange: "stroke-orange-600 dark:stroke-orange-400",
  danger: "stroke-red-600 dark:stroke-red-400",
  primary: "stroke-blue-600 dark:stroke-blue-400",
  neutral: "stroke-slate-600 dark:stroke-slate-300",
};

function Card({ children, className }) {
  return (
    <section
      className={cn(
        "rounded-xl border border-[#E5E7EB] bg-white shadow-soft transition duration-200 hover:-translate-y-0.5 hover:shadow-md dark:border-slate-800 dark:bg-slate-900",
        className
      )}
    >
      {children}
    </section>
  );
}

function Button({ children, variant = "default", className, ...props }) {
  const variants = {
    default: "bg-[#2563EB] text-white hover:bg-blue-700",
    secondary:
      "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800",
    danger: "bg-[#EF4444] text-white hover:bg-red-600",
    ghost: "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
  };

  return (
    <button
      className={cn(
        "inline-flex h-9 items-center justify-center gap-2 rounded-lg px-3 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-slate-950",
        variants[variant],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

function Badge({ children, tone = "neutral" }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-1 text-xs font-bold ring-1", toneClass[tone].soft)}>
      {children}
    </span>
  );
}

function Progress({ value, tone = "primary" }) {
  return (
    <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
      <div
        className={cn("h-full origin-left rounded-full animate-progress-fill", toneClass[tone].bg)}
        style={{ width: `${Math.max(0, Math.min(value, 100))}%` }}
      />
    </div>
  );
}

function SectionHeader({ title, description, action }) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-base font-bold text-[#111827] dark:text-white">{title}</h2>
        {description ? <p className="mt-1 text-sm text-[#6B7280] dark:text-slate-400">{description}</p> : null}
      </div>
      {action}
    </div>
  );
}

function ServerHeader({ server }) {
  const isOnline = server.status === "Online";
  return (
    <Card className="p-4">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Monitor className="h-5 w-5 text-blue-600" />
            <h1 className="truncate text-2xl font-extrabold tracking-tight text-[#111827] dark:text-white">{server.name}</h1>
            <Badge tone={isOnline ? "success" : "danger"}>{server.status}</Badge>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-sm text-[#6B7280] dark:text-slate-400 md:grid-cols-4 xl:grid-cols-7">
            <Meta label="IP" value={server.ip} />
            <Meta label="SO" value={server.os} />
            <Meta label="Ambiente" value={server.environment} />
            <Meta label="Grupo" value={server.group} />
            <Meta label="Responsable" value={server.owner} />
            <Meta label="Agente" value={server.agentStatus} />
            <Meta label="Ultimo check" value={server.lastCheck} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary">
            <Edit3 className="h-4 w-4" /> Editar
          </Button>
          <Button variant="secondary">
            <RefreshCcw className="h-4 w-4" /> Actualizar
          </Button>
          <Button variant="default">
            <Terminal className="h-4 w-4" /> Terminal
          </Button>
          <Button variant="danger">
            <Trash2 className="h-4 w-4" /> Eliminar
          </Button>
        </div>
      </div>
    </Card>
  );
}

function Meta({ label, value }) {
  return (
    <div className="min-w-0">
      <div className="text-[11px] font-bold uppercase tracking-wide text-slate-400">{label}</div>
      <div className="truncate font-semibold text-slate-700 dark:text-slate-200">{value || "-"}</div>
    </div>
  );
}

function KpiCard({ icon: Icon, label, value, progress, suffix = "%", tone }) {
  const resolvedTone = tone || utilizationTone(progress || 0);
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className={cn("rounded-lg p-2", toneClass[resolvedTone].soft)}>
          <Icon className="h-5 w-5" />
        </div>
        <span className={cn("text-xs font-bold", toneClass[resolvedTone].text)}>{progress ? `${progress}%` : "OK"}</span>
      </div>
      <div className="mt-4">
        <div className="text-sm font-semibold text-[#6B7280] dark:text-slate-400">{label}</div>
        <div className="mt-1 text-2xl font-extrabold text-[#111827] dark:text-white">
          {value}
          {suffix && typeof value === "number" ? suffix : ""}
        </div>
      </div>
      <div className="mt-4">
        <Progress value={progress || 100} tone={resolvedTone} />
      </div>
    </Card>
  );
}

function GeneralInfo({ server }) {
  const rows = [
    ["Hostname", server.hostname],
    ["Sistema Operativo", server.os],
    ["Kernel", server.kernel],
    ["Version", server.version],
    ["IP", server.ip],
    ["Grupo", server.group],
    ["Responsable", server.owner],
    ["Fecha creacion", server.createdAt],
    ["Ultimo monitoreo", server.lastCheck],
    ["Estado Agente", server.agentStatus],
  ];

  return (
    <Card className="p-4 lg:col-span-7">
      <SectionHeader title="Informacion General" description="Datos tecnicos y administrativos del equipo." />
      <dl className="grid grid-cols-1 gap-x-5 gap-y-3 md:grid-cols-2">
        {rows.map(([label, value]) => (
          <div key={label} className="rounded-lg border border-slate-100 p-3 dark:border-slate-800">
            <dt className="text-xs font-bold uppercase tracking-wide text-[#6B7280] dark:text-slate-500">{label}</dt>
            <dd className="mt-1 break-words text-sm font-semibold text-[#111827] dark:text-slate-100">{value}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function DiskCard({ disk }) {
  const tone = utilizationTone(disk.percent);
  return (
    <div className="rounded-xl border border-slate-100 p-3 transition hover:border-blue-200 hover:bg-blue-50/30 dark:border-slate-800 dark:hover:border-blue-900 dark:hover:bg-blue-950/20">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <HardDrive className="h-4 w-4 text-slate-500" />
          <span className="font-bold text-[#111827] dark:text-white">{disk.name}</span>
        </div>
        <span className={cn("text-sm font-extrabold", toneClass[tone].text)}>{disk.percent}%</span>
      </div>
      <div className="mt-3">
        <Progress value={disk.percent} tone={tone} />
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
        <Meta label="Capacidad" value={disk.capacity} />
        <Meta label="Usado" value={disk.used} />
        <Meta label="Libre" value={disk.free} />
      </div>
    </div>
  );
}

function DisksPanel({ disks }) {
  return (
    <Card className="p-4 lg:col-span-5">
      <SectionHeader title="Discos" description="Uso, capacidad y espacio libre por unidad." />
      <div className="grid gap-3">
        {disks.map((disk) => (
          <DiskCard key={disk.name} disk={disk} />
        ))}
      </div>
    </Card>
  );
}

function CredentialsTable({ credentials, onAdd }) {
  return (
    <Card className="p-4">
      <SectionHeader
        title="Credenciales SSH"
        description="Usuarios registrados para acceder al equipo."
        action={
          <Button onClick={onAdd}>
            <Plus className="h-4 w-4" /> Agregar credencial
          </Button>
        }
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[#6B7280] dark:border-slate-800">
              <th className="py-3">Usuario</th>
              <th>Puerto</th>
              <th>Ultima validacion</th>
              <th>Estado</th>
              <th className="text-right">Acciones</th>
            </tr>
          </thead>
          <tbody>
            {credentials.map((credential) => (
              <tr key={credential.id} className="border-b border-slate-100 transition hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/50">
                <td className="py-3 font-semibold text-[#111827] dark:text-white">{credential.user}</td>
                <td>{credential.port}</td>
                <td className="text-[#6B7280] dark:text-slate-400">{credential.lastValidation}</td>
                <td>
                  <Badge tone="success">{credential.status}</Badge>
                </td>
                <td>
                  <div className="flex justify-end gap-2">
                    <Button variant="ghost" className="h-8 px-2">
                      <Edit3 className="h-4 w-4" /> Editar
                    </Button>
                    <Button variant="ghost" className="h-8 px-2">
                      <Zap className="h-4 w-4" /> Probar
                    </Button>
                    <Button variant="ghost" className="h-8 px-2 text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950/30">
                      <Trash2 className="h-4 w-4" /> Eliminar
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function CredentialModal({ open, onClose }) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-4 backdrop-blur-sm">
      <Card className="w-full max-w-lg p-5">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-extrabold text-[#111827] dark:text-white">Agregar credencial SSH</h2>
            <p className="mt-1 text-sm text-[#6B7280] dark:text-slate-400">La clave se debe guardar cifrada en el backend.</p>
          </div>
          <Button variant="ghost" className="h-8 w-8 p-0" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>
        <form className="mt-5 grid gap-4">
          <Field label="Nombre" placeholder="Oracle DBA" />
          <Field label="Usuario" placeholder="oracle" />
          <Field label="Puerto SSH" placeholder="22" />
          <Field label="Clave" placeholder="********" type="password" />
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="secondary" onClick={onClose}>
              Cancelar
            </Button>
            <Button type="button" onClick={onClose}>
              Guardar credencial
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

function Field({ label, ...props }) {
  return (
    <label className="grid gap-1.5 text-sm font-bold text-[#111827] dark:text-slate-200">
      {label}
      <input
        className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 dark:border-slate-700 dark:bg-slate-950 dark:focus:ring-blue-950"
        {...props}
      />
    </label>
  );
}

function TerminalPanel({ credentials }) {
  const [output, setOutput] = useState("$ uptime\n 11:42:01 up 21 days, 4:18, 2 users, load average: 0.41, 0.38, 0.35\n");

  const quickCommands = ["uptime", "df -h", "free -m", "systemctl status monitoring-agent", "top -b -n1 | head"];

  return (
    <Card className="overflow-hidden p-0">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-950 px-4 py-3 text-slate-100">
        <div className="flex items-center gap-2">
          <Terminal className="h-5 w-5 text-blue-400" />
          <div>
            <h2 className="font-extrabold">Terminal Linux</h2>
            <p className="text-xs text-slate-400">Consola estilo VSCode para ejecucion remota.</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" className="text-slate-200 hover:bg-slate-800">
            <Copy className="h-4 w-4" /> Copiar
          </Button>
          <Button variant="ghost" className="text-slate-200 hover:bg-slate-800">
            <Download className="h-4 w-4" /> Descargar
          </Button>
        </div>
      </div>
      <div className="grid gap-3 bg-slate-950 p-4">
        <div className="grid gap-3 lg:grid-cols-[240px_240px_1fr_auto]">
          <select className="h-10 rounded-lg border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100">
            {credentials.map((credential) => (
              <option key={credential.id}>{credential.user}:{credential.port}</option>
            ))}
          </select>
          <select className="h-10 rounded-lg border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100">
            {quickCommands.map((command) => (
              <option key={command}>{command}</option>
            ))}
          </select>
          <input className="h-10 rounded-lg border border-slate-700 bg-slate-900 px-3 font-mono text-sm text-slate-100" defaultValue="uptime" />
          <Button onClick={() => setOutput((current) => `${current}\n$ df -h\n/dev/sda1 120G 98G 22G 82% /\n`)}>
            <Play className="h-4 w-4" /> Ejecutar
          </Button>
        </div>
        <pre className="terminal-scrollbar max-h-[340px] min-h-[260px] overflow-auto rounded-xl border border-slate-800 bg-black p-4 font-mono text-sm leading-6 text-emerald-300">
          {output}
        </pre>
      </div>
    </Card>
  );
}

function MetricChart({ title, icon: Icon, values, tone = "primary" }) {
  const points = useMemo(() => {
    if (!values.length) return "";
    return values
      .map((value, index) => {
        const x = (index / Math.max(values.length - 1, 1)) * 300;
        const y = 100 - value;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }, [values]);

  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className={cn("h-4 w-4", toneClass[tone].text)} />
          <h3 className="font-bold text-[#111827] dark:text-white">{title}</h3>
        </div>
        <Badge tone={tone}>{values[values.length - 1]}%</Badge>
      </div>
      <svg viewBox="0 0 300 110" className="h-44 w-full">
        <line x1="0" x2="300" y1="25" y2="25" className="stroke-slate-200 dark:stroke-slate-800" />
        <line x1="0" x2="300" y1="55" y2="55" className="stroke-slate-200 dark:stroke-slate-800" />
        <line x1="0" x2="300" y1="85" y2="85" className="stroke-slate-200 dark:stroke-slate-800" />
        <polyline points={points} fill="none" className={cn("stroke-[4] stroke-linecap-round stroke-linejoin-round", strokeClass[tone])} />
      </svg>
    </Card>
  );
}

function MetricsGrid({ charts }) {
  const [range, setRange] = useState("1h");
  const ranges = ["1h", "6h", "24h", "7 dias", "30 dias"];
  return (
    <Card className="p-4">
      <SectionHeader
        title="Graficos"
        description="Metricas historicas por ventana de tiempo."
        action={
          <div className="flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-800">
            {ranges.map((item) => (
              <button
                key={item}
                onClick={() => setRange(item)}
                className={cn(
                  "rounded-md px-3 py-1.5 text-xs font-bold transition",
                  range === item ? "bg-white text-blue-700 shadow-sm dark:bg-slate-950 dark:text-blue-300" : "text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
                )}
              >
                {item}
              </button>
            ))}
          </div>
        }
      />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        <MetricChart title="CPU" icon={Cpu} values={charts.cpu} tone="primary" />
        <MetricChart title="RAM" icon={MemoryStick} values={charts.ram} tone="warning" />
        <MetricChart title="Disco" icon={HardDrive} values={charts.disk} tone="orange" />
        <MetricChart title="Red" icon={Network} values={charts.network} tone="success" />
      </div>
    </Card>
  );
}

function EventsTable({ events }) {
  const severityTone = {
    Info: "primary",
    Warning: "warning",
    Critical: "danger",
  };
  const severityIcon = {
    Info: CircleDot,
    Warning: AlertTriangle,
    Critical: AlertTriangle,
  };

  return (
    <Card className="p-4">
      <SectionHeader title="Eventos recientes" description="Ultimos eventos y alertas del servidor." />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[#6B7280] dark:border-slate-800">
              <th className="py-3">Fecha</th>
              <th>Tipo</th>
              <th>Severidad</th>
              <th>Mensaje</th>
              <th>Icono</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => {
              const Icon = severityIcon[event.severity];
              return (
                <tr key={`${event.date}-${event.message}`} className="border-b border-slate-100 transition hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/50">
                  <td className="py-3 text-[#6B7280] dark:text-slate-400">{event.date}</td>
                  <td className="font-semibold">{event.type}</td>
                  <td>
                    <Badge tone={severityTone[event.severity]}>{event.severity}</Badge>
                  </td>
                  <td>{event.message}</td>
                  <td>
                    <Icon className={cn("h-4 w-4", toneClass[severityTone[event.severity]].text)} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Skeleton() {
  return <div className="h-4 animate-pulse rounded bg-slate-200 dark:bg-slate-800" />;
}

export default function ServerDetailPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const server = serverMock;

  return (
    <div className="min-h-screen bg-[#F8FAFC] p-4 text-[#111827] dark:bg-slate-950 dark:text-slate-100 lg:p-6">
      <div className="mx-auto grid max-w-[1680px] grid-cols-12 gap-4">
        <div className="col-span-12">
          <ServerHeader server={server} />
        </div>

        <div className="col-span-12 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
          <KpiCard icon={Cpu} label="CPU" value={server.kpis.cpu} progress={server.kpis.cpu} />
          <KpiCard icon={MemoryStick} label="RAM" value={server.kpis.ram} progress={server.kpis.ram} />
          <KpiCard icon={HardDrive} label="Disco" value={server.kpis.disk} progress={server.kpis.disk} />
          <KpiCard icon={Clock3} label="Uptime" value={server.kpis.uptime} progress={100} suffix="" tone="success" />
          <KpiCard icon={Activity} label="Ultimo Check" value={server.lastCheck} progress={100} suffix="" tone="primary" />
          <KpiCard icon={ShieldCheck} label="Seguridad" value={server.kpis.security} progress={server.kpis.security} />
        </div>

        <div className="col-span-12 grid grid-cols-1 gap-4 lg:grid-cols-12">
          <GeneralInfo server={server} />
          <DisksPanel disks={server.disks} />
        </div>

        <div className="col-span-12">
          <CredentialsTable credentials={server.credentials} onAdd={() => setModalOpen(true)} />
        </div>

        <div className="col-span-12">
          <TerminalPanel credentials={server.credentials} />
        </div>

        <div className="col-span-12">
          <MetricsGrid charts={server.charts} />
        </div>

        <div className="col-span-12">
          <EventsTable events={server.events} />
        </div>
      </div>

      <CredentialModal open={modalOpen} onClose={() => setModalOpen(false)} />
    </div>
  );
}
