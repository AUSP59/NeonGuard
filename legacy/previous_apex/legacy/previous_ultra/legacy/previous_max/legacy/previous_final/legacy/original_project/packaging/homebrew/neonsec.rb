class Neonsec < Formula
  desc "Neon Secure Network System"
  homepage "https://example.org/neonsec"
  url "file://#{Dir.pwd}/neonsec-1.0.0.tar.gz"
  version "1.0.0"
  license "Apache-2.0"
  def install
    system "cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Release"
    system "cmake", "--build", "build", "-j"
    bin.install "build/neonsec"
    man1.install "docs/neonsec.1"
  end
  test do
    system "#{bin}/neonsec", "--version"
  end
end
