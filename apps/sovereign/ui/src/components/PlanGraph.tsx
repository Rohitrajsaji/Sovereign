// Callers: Goal detail Plan tab.
// API: left-to-right DAG of Controller tasks. Color is not the only status cue.
// Schema: GoalDetail.tasks from control-api-v2.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Plan: an @xyflow/react DAG laid out left to right.

import {
  Background,
  Controls,
  type Edge,
  type Node,
  ReactFlow,
} from "@xyflow/react";
import { Circle, CircleCheck, CircleDashed, CircleX, Pause } from "lucide-react";
import { useMemo } from "react";
import { StatusPill } from "./ui";

import "@xyflow/react/dist/style.css";

type TaskLike = Record<string, unknown>;

function taskField(task: TaskLike, key: string): string {
  const value = task[key];
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  if (typeof value === "number") {
    return String(value);
  }
  return "";
}

function TaskIcon({ state }: { state: string }) {
  if (/complete|verified|success/i.test(state)) {
    return <CircleCheck size={14} aria-hidden="true" />;
  }
  if (/fail|error|unknown/i.test(state)) {
    return <CircleX size={14} aria-hidden="true" />;
  }
  if (/pause|wait|defer/i.test(state)) {
    return <Pause size={14} aria-hidden="true" />;
  }
  if (/run|active/i.test(state)) {
    return <Circle size={14} aria-hidden="true" />;
  }
  return <CircleDashed size={14} aria-hidden="true" />;
}

function TaskNode({ data }: { data: { label: string; state: string } }) {
  return (
    <div className="sv-node">
      <TaskIcon state={data.state} />
      <div>
        <StatusPill status={data.state} />
        <p>{data.label}</p>
      </div>
    </div>
  );
}

const nodeTypes = { task: TaskNode };

export function PlanGraph({ tasks }: { tasks: TaskLike[] }) {
  const { nodes, edges } = useMemo(() => {
    const nextNodes: Node[] = tasks.slice(0, 16).map((task, index) => {
      const id = taskField(task, "task_id") || `task-${index}`;
      const state = taskField(task, "state") || taskField(task, "status") || "queued";
      const label = taskField(task, "title") || taskField(task, "objective") || id;
      return {
        id,
        type: "task",
        position: { x: index * 220, y: 40 + (index % 2) * 80 },
        data: { label, state },
        sourcePosition: "right",
        targetPosition: "left",
      } as Node;
    });
    const nextEdges: Edge[] = nextNodes.slice(1).map((node, index) => ({
      id: `e-${index}`,
      source: nextNodes[index]?.id ?? "",
      target: node.id,
    }));
    return { nodes: nextNodes, edges: nextEdges };
  }, [tasks]);

  if (tasks.length === 0) {
    return (
      <p className="sv-muted">No compiled tasks yet. The Controller has not activated a plan revision.</p>
    );
  }

  return (
    <div className="sv-graph" aria-label="Task graph">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView proOptions={{ hideAttribution: true }}>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}

export function taskCount(tasks: unknown): number {
  return Array.isArray(tasks) ? tasks.length : 0;
}
