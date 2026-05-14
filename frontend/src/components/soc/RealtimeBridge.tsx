import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { getToken, setWebsocketStatus, wsUrl } from "@/lib/api";
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

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;

    const token = getToken();
    if (!canQueryBackend() || !token) {
      setWebsocketStatus("missing auth");
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
      if (!closedByEffect && getToken()) {
        setWebsocketStatus("reconnecting");
        reconnectTimerRef.current = setTimeout(() => {
          setReconnectAttempt((value) => value + 1);
        }, 2500);
      } else {
        setWebsocketStatus("disconnected");
      }
    };

    return () => {
      closedByEffect = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      socket.close();
    };
  }, [mounted, queryClient, reconnectAttempt]);

  return null;
}
