# Reproducible 15-second terminal recording for zerobom
# Render locally with: vhs docs/assets/demo.tape
# Or trigger .github/workflows/render-demo.yml in GitHub Actions.

Output docs/assets/demo.gif

Require zerobom

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 700
Set Padding 20
Set TypingSpeed 40ms
Set Theme "TokyoNight"

Type "zerobom demo"
Sleep 400ms
Enter
Sleep 4s

Type "zerobom backends"
Sleep 400ms
Enter
Sleep 3s
