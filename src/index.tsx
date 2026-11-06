import {
  ButtonItem,
  PanelSection,
  PanelSectionRow,
  staticClasses,
} from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useEffect, useState } from "react";
import type { ChangeEvent } from "react";
import { FaEye } from "react-icons/fa";

type PluginState = {
  fov: number;
  default_fov: number;
  min_fov: number;
  max_fov: number;
  step: number;
  game_running: boolean;
  game_ready: boolean;
  pid: number | null;
  age_seconds: number;
  wait_seconds: number;
  busy: boolean;
  pending: boolean;
  message: string;
  error: string;
};

const getState = callable<[], PluginState>("get_state");
const setFov = callable<[fov: number], PluginState>("set_fov");
const resetFov = callable<[], PluginState>("reset_fov");

const formatFov = (value: number) => value.toFixed(2);

function Content() {
  const [state, setState] = useState<PluginState | undefined>();

  const refreshState = async () => {
    const nextState = await getState();
    setState(nextState);
  };

  useEffect(() => {
    refreshState();
    const interval = window.setInterval(refreshState, 5000);
    return () => window.clearInterval(interval);
  }, []);

  const updateState = (nextState: PluginState) => {
    setState(nextState);
    if (nextState.error) {
      toaster.toast({
        title: "FOV patch failed",
        body: nextState.error,
      });
    }
  };

  const commitFov = async (value: number) => {
    updateState(await setFov(value));
  };

  const onSliderChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const value = Number(event.currentTarget.value);
    await commitFov(value);
  };

  const onReset = async () => {
    updateState(await resetFov());
  };

  if (!state) {
    return (
      <PanelSection title="DSR FOV">
        <PanelSectionRow>
          <div>Loading...</div>
        </PanelSectionRow>
      </PanelSection>
    );
  }

  return (
    <PanelSection title="DSR FOV">
      <PanelSectionRow>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>FOV</span>
            <span>{formatFov(state.fov)}</span>
          </div>
          <input
            type="range"
            min={state.min_fov}
            max={state.max_fov}
            step={state.step}
            value={state.fov}
            onChange={onSliderChange}
            style={{ width: "100%" }}
          />
        </div>
      </PanelSectionRow>
      <PanelSectionRow>
        <ButtonItem layout="below" onClick={onReset}>
          Reset to Default
        </ButtonItem>
      </PanelSectionRow>
      <PanelSectionRow>
        <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
          <div>{state.message}</div>
          {state.pid ? <div>PID: {state.pid}</div> : null}
          {state.pending ? <div>Pending change queued.</div> : null}
        </div>
      </PanelSectionRow>
    </PanelSection>
  );
}

export default definePlugin(() => {
  return {
    name: "DSR FOV",
    titleView: <div className={staticClasses.Title}>DSR FOV</div>,
    content: <Content />,
    icon: <FaEye />,
  };
});
