import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { getToken, onAuthChange, setWebsocketStatus, wsUrl } from "@/lib/api";
import { applyRealtimeEventToCache, emitRealtimeEvent, type RealtimeEvent } from "@/lib/live-data";
import { canQueryBackend } from "@/lib/presentation";

const SUBSCRIPTIONS = [
  "soc.alert.created",
  "soc.incident.created",
  "soc.response_action.created",
  "correlation.created",
  "correlation.updated",
  "incident.updated",
  "timeline.updated",
  "system.connected",
  "system.subscriptions.updated",
];

export function RealtimeBridge() {
  const queryClient = useQueryClient();
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const [mounted, setMounted] = useState(false);
  const [token, setTokenState] = useState<string | null>(() => getToken());

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => onAuthChange(() => setTokenState(getToken())), []);

  useEffect(() => {
    if (!mounted) return;

    if (!canQueryBackend() || !token) {
      setWebsocketStatus(token ? "disabled" : "missing auth");
      return;
    }

    let closedByEffect = false;
    setWebsocketStatus("connecting");

    const socket = new WebSocket(wsUrl("/ws/alerts"));
    socketRef.current = socket;

    socket.onopen = () => {
      setWebsocketStatus("connected");
      socket.send(
        JSON.stringify({
          action: "subscribe",
          replace: true,
          event_types: SUBSCRIPTIONS,
        }),
      );
    };

    socket.onmessage = (message) => {
      let event: RealtimeEvent;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }

      emitRealtimeEvent(event);
      applyRealtimeEventToCache(queryClient, event);
    };

    socket.onerror = () => {
      setWebsocketStatus("error");
    };

    socket.onclose = () => {
      if (socketRef.current === socket) {
        socketRef.current = null;
      }
      if (!closedByEffect && getToken() && ![1008, 1011].includes(socket.code)) {
        setWebsocketStatus("reconnecting");
        const backoffMs = Math.min(30_000, 1_000 * 2 ** Math.min(reconnectAttempt, 4));
        reconnectTimerRef.current = setTimeout(() => {
          setReconnectAttempt((value) => value + 1);
        }, backoffMs);
      } else {
        setWebsocketStatus("disconnected");
      }
    };

    return () => {
      closedByEffect = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
      socket.close();
    };
  }, [mounted, queryClient, reconnectAttempt, token]);

  return null;
}
