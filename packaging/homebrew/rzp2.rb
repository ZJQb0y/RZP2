# Homebrew formula for RZP2.
#
# 提交到 homebrew-core 或 tap 前，请把 `sha256` 替换为对应源码包的真实校验和：
#   curl -sL https://github.com/ZJQb0y/rzp2/archive/refs/tags/v0.8.0.tar.gz | shasum -a 256
class Rzp2 < Formula
  desc "From-scratch hybrid encryption compression tool (LZMA + ML-KEM + ChaCha20-Poly1305)"
  homepage "https://github.com/ZJQb0y/rzp2"
  url "https://github.com/ZJQb0y/rzp2/archive/refs/tags/v0.8.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256"
  license "MIT OR Apache-2.0"
  head "https://github.com/ZJQb0y/rzp2.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "."
    man1.install "man/rzp2.1"

    # shell Tab 补全脚本（bash / zsh / fish）。
    (bash_completion/"rzp2").write Utils.popen_read(bin/"rzp2", "completion", "bash")
    (zsh_completion/"_rzp2").write Utils.popen_read(bin/"rzp2", "completion", "zsh")
    (fish_completion/"rzp2.fish").write Utils.popen_read(bin/"rzp2", "completion", "fish")
  end

  test do
    system "#{bin}/rzp2", "--version"
    (testpath/"hello.txt").write "hello world\n"
    system "#{bin}/rzp2", "compress", "hello.txt", "-o", "hello.txt.rzp2"
    assert_predicate testpath/"hello.txt.rzp2", :exist?
  end
end
