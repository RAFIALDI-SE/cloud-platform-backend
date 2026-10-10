const http = require("node:http");

const PORT = 3000;

const server = http.createServer((req, res) => {
  if (req.url === "/api/health" && req.method === "GET") {
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
    });

    res.end(
      JSON.stringify({
        status: "ok",
        message: "ZeixonCloudHouse Backend is running",
      }),
    );

    return;
  }

  res.writeHead(404, {
    "Content-Type": "application/json; charset=utf-8",
  });

  res.end(
    JSON.stringify({
      status: "error",
      message: "Endpoint tidak ditemukan",
    }),
  );
});

server.listen(PORT, () => {
  console.log(`Backend berjalan di http://localhost:${PORT}`);
});
