import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { Case, DetectedDevice, Device } from "../api/types";
import { useEvents } from "../lib/events";
import { formatBytes } from "../lib/format";
import Overview from "../components/Overview";

export interface ImagingState {
  deviceId: number;
  name: string;
  pct: number;
  step: string;
}

export default function Dashboard() {
  const [cases, setCases] = useState<Case[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [detected, setDetected] = useState<DetectedDevice[]>([]);
  const [activeCase, setActiveCase] = useState<number | null>(null);
  const [busy, setBusy] = useState<string>("");
  const [imaging, setImaging] = useState<ImagingState | null>(null);
  const { subscribe } = useEvents();
  const navigate = useNavigate();

  const reload = async () => {
    const [c, d] = await Promise.all([api.listCases(), api.listDevices()]);
    setCases(c);
    setDevices(d);
    if (!activeCase && c.length) setActiveCase(c[0].id);
  };

  const detect = async () => {
    setBusy("detect");
    try {
      setDetected(await api.detectDevices());
    } finally {
      setBusy("");
    }
  };

  useEffect(() => {
    reload();
    detect();
  }, []);

  useEffect(() => {
    return subscribe((ev) => {
      if (ev.type === "device_hotplug") detect();
      if (ev.type === "imaging_completed") reload();
      if (ev.type === "imaging_progress") {
        const d = ev.data as { device_id: number; progress: number; step: string };
        setImaging((prev) =>
          prev && prev.deviceId === d.device_id ? { ...prev, pct: d.progress, step: d.step } : prev
        );
      }
    });
  }, [subscribe]);

  return (
    <div>
      <h1 className="page-title">Хяналтын самбар</h1>
      <p className="page-sub">Зөөврийн төхөөрөмжийг таниж, хэрэгт бүртгэн, read-only шинжилгээ эхлүүлнэ.</p>

      <Overview />

      <div className="grid grid-2">
        <CasePanel cases={cases} activeCase={activeCase} setActiveCase={setActiveCase} onCreated={reload} />
        <DetectPanel detected={detected} busy={busy} onDetect={detect} activeCase={activeCase} onRegistered={reload} />
      </div>

      <RegisteredDevices
        devices={devices}
        cases={cases}
        onChanged={reload}
        setBusy={setBusy}
        busy={busy}
        navigate={navigate}
        setImaging={setImaging}
      />

      {imaging && <ImagingOverlay state={imaging} />}
    </div>
  );
}

const IMAGING_STAGES = [
  { key: "ro", label: "Write-block (read-only)", until: 5 },
  { key: "read", label: "Дүрс уншиж байна (bit-by-bit)", until: 60 },
  { key: "hash", label: "Hash тооцож, баталгаажуулж байна", until: 95 },
  { key: "scan", label: "Шинжилгээ эхлүүлж байна", until: 101 },
];

function ImagingOverlay({ state }: { state: ImagingState }) {
  const pct = Math.max(0, Math.min(100, Math.round(state.pct)));
  const activeIdx = IMAGING_STAGES.findIndex((s) => pct < s.until);

  return (
    <div className="overlay">
      <div className="overlay-card">
        <h2 className="overlay-title">Forensic дүрс бэлтгэж байна</h2>
        <p className="overlay-sub">
          <span className="mono">{state.name}</span> төхөөрөмжөөс зөвхөн унших горимоор хуулбар авч байна.
        </p>

        <div className="progress-wrap">
          <div className="progress-bar" style={{ width: `${Math.max(pct, 3)}%` }}>
            <span className="progress-shimmer" />
          </div>
        </div>
        <div className="progress-meta">
          <span>{state.step || "Бэлтгэж байна…"}</span>
          <span className="mono">{pct}%</span>
        </div>

        <ul className="stage-list">
          {IMAGING_STAGES.map((s, i) => {
            const done = activeIdx === -1 || i < activeIdx;
            const active = i === activeIdx;
            return (
              <li key={s.key} className={done ? "done" : active ? "active" : ""}>
                <span className="stage-icon">{done ? "✓" : active ? <span className="spinner" /> : "○"}</span>
                {s.label}
              </li>
            );
          })}
        </ul>

        <p className="overlay-hint">
          Том диск дээр энэ хэсэг хэдэн минут үргэлжилж болно. Цонхыг хаахгүй байна уу.
        </p>
      </div>
    </div>
  );
}

function CasePanel({
  cases,
  activeCase,
  setActiveCase,
  onCreated,
}: {
  cases: Case[];
  activeCase: number | null;
  setActiveCase: (id: number) => void;
  onCreated: () => void;
}) {
  const [form, setForm] = useState({ case_number: "", title: "", investigator: "", description: "" });
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    try {
      const c = await api.createCase(form);
      setForm({ case_number: "", title: "", investigator: "", description: "" });
      setActiveCase(c.id);
      onCreated();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <div className="panel">
      <h2>Хэрэг</h2>
      <div className="field">
        <label>Идэвхтэй хэрэг (шинжилгээнд хэрэглэнэ)</label>
        <select value={activeCase ?? ""} onChange={(e) => setActiveCase(Number(e.target.value))}>
          <option value="">— сонгох —</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>
              {c.case_number} · {c.title}
            </option>
          ))}
        </select>
      </div>

      <h3>Шинэ хэрэг үүсгэх</h3>
      <div className="field">
        <label>Хэргийн дугаар</label>
        <input type="text" value={form.case_number} onChange={(e) => setForm({ ...form, case_number: e.target.value })} />
      </div>
      <div className="field">
        <label>Гарчиг</label>
        <input type="text" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
      </div>
      <div className="field">
        <label>Шинжээч</label>
        <input type="text" value={form.investigator} onChange={(e) => setForm({ ...form, investigator: e.target.value })} />
      </div>
      {err && <div style={{ color: "var(--red)", fontSize: 12, marginBottom: 8 }}>{err}</div>}
      <button className="btn" disabled={!form.case_number || !form.title} onClick={submit}>
        Хэрэг үүсгэх
      </button>
    </div>
  );
}

function DetectPanel({
  detected,
  busy,
  onDetect,
  activeCase,
  onRegistered,
}: {
  detected: DetectedDevice[];
  busy: string;
  onDetect: () => void;
  activeCase: number | null;
  onRegistered: () => void;
}) {
  const register = async (dev: DetectedDevice) => {
    await api.registerDevice(dev.dev_path, activeCase);
    onRegistered();
  };

  return (
    <div className="panel">
      <div className="row-flex">
        <h2 style={{ margin: 0 }}>Илрүүлсэн төхөөрөмж</h2>
        <div className="spacer" />
        <button className="btn secondary sm" disabled={busy === "detect"} onClick={onDetect}>
          {busy === "detect" ? "Хайж байна…" : "Дахин илрүүлэх"}
        </button>
      </div>
      {detected.length === 0 ? (
        <div className="empty">Зөөврийн төхөөрөмж олдсонгүй. USB/SD холбоод "Дахин илрүүлэх" дарна уу.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Зам</th>
              <th>Нэр</th>
              <th>Хэмжээ</th>
              <th>FS</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {detected.map((d) => (
              <tr key={d.dev_path}>
                <td className="mono">{d.dev_path}</td>
                <td>{d.name || "—"}</td>
                <td>{formatBytes(d.size_bytes)}</td>
                <td>{d.fs_type || "—"}</td>
                <td>
                  <button className="btn sm" onClick={() => register(d)}>
                    Бүртгэх
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function RegisteredDevices({
  devices,
  cases,
  onChanged,
  setBusy,
  busy,
  navigate,
  setImaging,
}: {
  devices: Device[];
  cases: Case[];
  onChanged: () => void;
  setBusy: (s: string) => void;
  busy: string;
  navigate: ReturnType<typeof useNavigate>;
  setImaging: (s: ImagingState | null) => void;
}) {
  const caseLabel = (id: number | null) => cases.find((c) => c.id === id)?.case_number ?? "—";

  const readOnly = async (id: number) => {
    setBusy(`ro-${id}`);
    try {
      await api.setReadOnly(id);
      onChanged();
    } finally {
      setBusy("");
    }
  };

  const startQuickScan = async (dev: Device) => {
    setBusy(`scan-${dev.id}`);
    try {
      if (!dev.read_only) await api.setReadOnly(dev.id);
      const scan = await api.createScan(dev.id, null, {
        use_image: false,
        quick_scan: true,
        recover_files: true,
        run_carving: false,
        run_recycle: true,
        run_named_tools: true,
        max_recover_size_mb: 512,
      });
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      alert("Шинжилгээ эхлүүлэхэд алдаа: " + (e as Error).message);
    } finally {
      setBusy("");
    }
  };

  const startFullScan = async (dev: Device) => {
    setBusy(`full-${dev.id}`);
    const name = dev.name || dev.dev_path;
    setImaging({ deviceId: dev.id, name, pct: 0, step: "Бэлтгэж байна…" });
    try {
      if (!dev.read_only) {
        setImaging({ deviceId: dev.id, name, pct: 2, step: "Write-block (read-only)…" });
        await api.setReadOnly(dev.id);
      }
      setImaging({ deviceId: dev.id, name, pct: 5, step: "Бүтэн дүрс уншиж байна (удаан)…" });
      const img = await api.acquireImage(dev.id);
      setImaging({ deviceId: dev.id, name, pct: 98, step: "Шинжилгээ эхлүүлж байна…" });
      const scan = await api.createScan(dev.id, img.id, {
        use_image: true,
        quick_scan: false,
        recover_files: true,
        run_carving: false,
        run_recycle: true,
        run_named_tools: true,
        max_recover_size_mb: 512,
      });
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      alert("Дүрс авах/шинжлэхэд алдаа: " + (e as Error).message);
    } finally {
      setImaging(null);
      setBusy("");
    }
  };

  return (
    <div className="panel">
      <h2>Бүртгэгдсэн төхөөрөмжүүд</h2>
      {devices.length === 0 ? (
        <div className="empty">Хараахан төхөөрөмж бүртгээгүй байна.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Зам</th>
              <th>Нэр</th>
              <th>Хэрэг</th>
              <th>Хэмжээ</th>
              <th>Төлөв</th>
              <th>Read-only</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                <td className="mono">{d.dev_path}</td>
                <td>{d.name || "—"}</td>
                <td>{caseLabel(d.case_id)}</td>
                <td>{formatBytes(d.size_bytes)}</td>
                <td>
                  <span className={`state state-${d.state}`}>{d.state}</span>
                </td>
                <td>{d.read_only ? <span className="dot on" /> : <span className="dot off" />}</td>
                <td>
                  <div className="row-flex">
                    {!d.read_only && (
                      <button className="btn secondary sm" disabled={busy === `ro-${d.id}`} onClick={() => readOnly(d.id)}>
                        Write-block
                      </button>
                    )}
                    <button
                      className="btn sm"
                      disabled={busy === `scan-${d.id}` || busy === `full-${d.id}`}
                      onClick={() => startQuickScan(d)}
                      title="TSK + ntfsundelete — анхны нэртэй, хурдан"
                    >
                      {busy === `scan-${d.id}` ? "Шинжилж байна…" : "Хурдан шинжилгээ"}
                    </button>
                    <button
                      className="btn secondary sm"
                      disabled={busy === `scan-${d.id}` || busy === `full-${d.id}`}
                      onClick={() => startFullScan(d)}
                      title="Бүтэн дүрс (dd) + нэртэй сэргээлт — уdaан"
                    >
                      {busy === `full-${d.id}` ? "Дүрс авч байна…" : "Бүрэн дүрс"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
