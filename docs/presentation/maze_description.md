# Developer-Focused Maze Security Diagram: Visual Concept

This diagram illustrates the architectural difference between logical code boundaries and kernel-enforced sandboxing within a single, continuous JVM process space, visualized as a shared maze with two distinct zones.

---

## The Unsafe Zone: Unenforced Logical Boundaries (Traditional JVM)
* **Concept:** Represents areas of the application relying solely on JVM package, class, or module boundaries. These exist logically in code but have no OS-level enforcement.
* **Visual Representation:**
  * In this section of the maze, the boundary "walls" are depicted as flat, low-lying, ankle-high curb lines or faint, dashed cyan stripes painted on the floor.
  * A red, translucent silhouette of an attacker (representing arbitrary code execution/exploit) is shown stepping directly over these flat ground markings with zero effort or resistance.
  * A red arrow shows the attacker's path bypassing these logical markings to reach unprotected resources.
* **Key Metaphor:** "Lines on the floor" — visible code organization, but physically non-enforcing against low-level exploits.

---

## The Safe Zone: Kernel-Enforced Boundaries (Mazewall Sandbox)
* **Concept:** Represents areas of the application protected by thread-scoped and process-wide sandboxing using Linux Seccomp-BPF and Landlock LSM.
* **Visual Representation:**
  * Within the same maze, the boundaries transition into towering, thick, solid, glowing blue structural walls.
  * An attacker outline attempting to cross one of these walls is physically blocked by a glowing orange-red shield ripple (representing a kernel-level `EPERM` / `EACCES` syscall rejection).
  * A legitimate, green-glowing execution path navigates smoothly along the authorized corridors (the Software Bill of Behavior contract).
* **Key Metaphor:** "Physical walls" — OS-kernel-enforced boundaries that remain secure even if code inside the zone is compromised.

---

## Design Token Reference
* **Logical Boundaries (Unsafe Zone):** Faint dashed Cyan (`#00f0ff`) stripes or low curblines on the floor.
* **Kernel-Enforced Boundaries (Safe Zone):** Solid, towering Cobalt Blue (`#0044ff`) walls.
* **Attacker/Rejection:** Red (`#ff3333`) silhouette / Orange-Red (`#ff6600`) impact ripple.
* **Legitimate Execution:** Emerald Green (`#00ff66`) path.
* **Composition:** A single, continuous maze perspective displaying the visual transition from low ground stripes (Unsafe Zone) to towering physical barriers (Safe Zone).

---
**Saved to project repository at:** `docs/presentation/maze_security_walls_new.png`
