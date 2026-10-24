import { useMemo, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { cx } from "./ui";

export type Column<T> = {
  key: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Value used for sorting; omit to make the column unsortable. */
  sort?: (row: T) => string | number;
  className?: string;
  headerClassName?: string;
};

type SortState = { key: string; dir: "asc" | "desc" } | null;

/**
 * Sortable table. Sorting state lives here, so live data refreshes replace
 * rows without resetting the operator's chosen order.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  initialSort = null,
  empty,
  dense,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  initialSort?: SortState;
  empty?: ReactNode;
  dense?: boolean;
}) {
  const [sort, setSort] = useState<SortState>(initialSort);
  const sorted = useMemo(() => {
    const col = sort ? columns.find((c) => c.key === sort.key) : undefined;
    if (!sort || !col?.sort) return rows;
    const get = col.sort;
    const out = [...rows];
    out.sort((a, b) => {
      const x = get(a);
      const y = get(b);
      const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" });
      return sort.dir === "asc" ? c : -c;
    });
    return out;
  }, [rows, sort, columns]);

  const toggle = (key: string) =>
    setSort((s) => (s?.key === key ? (s.dir === "asc" ? { key, dir: "desc" } : null) : { key, dir: "asc" }));

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-border">
            {columns.map((c) => {
              const active = sort?.key === c.key;
              const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
              return (
                <th
                  key={c.key}
                  scope="col"
                  aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : undefined}
                  className={cx("px-3 py-2 text-[11.5px] font-semibold tracking-wide text-faint uppercase whitespace-nowrap", c.headerClassName)}
                >
                  {c.sort ? (
                    <button type="button" onClick={() => toggle(c.key)} className={cx("inline-flex items-center gap-1 uppercase hover:text-fg", active && "text-fg")}>
                      {c.header}
                      <Icon className={cx("size-3", !active && "opacity-40")} aria-hidden />
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td colSpan={columns.length}>{empty}</td>
            </tr>
          ) : (
            sorted.map((row) => (
              <tr
                key={rowKey(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={cx("border-b border-border last:border-b-0", onRowClick && "cursor-pointer hover:bg-surface-2")}
              >
                {columns.map((c) => (
                  <td key={c.key} className={cx("px-3 align-middle", dense ? "py-1.5" : "py-2.5", c.className)}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
