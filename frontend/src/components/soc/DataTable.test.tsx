import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DataTable, type Column } from "./DataTable";

type Row = {
  id: string;
  title: string;
  severity: string;
};

const columns: Column<Row>[] = [
  {
    key: "title",
    header: "Title",
    render: (row) => row.title,
  },
  {
    key: "severity",
    header: "Severity",
    render: (row) => row.severity,
  },
];

describe("DataTable", () => {
  it("filters rows from the search box", async () => {
    const user = userEvent.setup();

    render(
      <DataTable
        rows={[
          { id: "1", title: "SSH brute force", severity: "high" },
          { id: "2", title: "Normal login", severity: "low" },
        ]}
        columns={columns}
        searchKeys={["title", "severity"]}
      />,
    );

    await user.type(screen.getByPlaceholderText("Search…"), "brute");

    expect(screen.getByText("SSH brute force")).toBeInTheDocument();
    expect(screen.queryByText("Normal login")).not.toBeInTheDocument();
  });

  it("shows the empty state when there are no rows", () => {
    render(<DataTable rows={[]} columns={columns} emptyTitle="No alerts" />);

    expect(screen.getByText("No alerts")).toBeInTheDocument();
  });
});
