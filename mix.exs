defmodule Strap.Mixfile do
  use Mix.Project

  def project do
    [
      app: :strap,
      version: "0.1.0",
      elixir: "~> 1.3",
      start_permanent: Mix.env == :prod,
      deps: deps(),
      package: package,
      description: """
      Lightweight SRP6/SRP6a (Secure Remote Password) library
      """
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 0.5", only: :dev, runtime: false},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Tony Wooster"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub": "https://github.com/twooster/strap"}
    ]
  end
end
