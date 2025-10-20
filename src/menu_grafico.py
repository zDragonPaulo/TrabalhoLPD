import tkinter as tk
from tkinter import ttk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Menu de")
        self.geometry("800x500")

        # Estilo moderno
        self.configure(bg="#f3f3f3")

        # Frame lateral (sidebar)
        sidebar = tk.Frame(self, bg="#e6e6e6", width=200)
        sidebar.pack(side="left", fill="y")

        # Frame de conteúdo
        self.content = tk.Frame(self, bg="white")
        self.content.pack(side="right", expand=True, fill="both")

        # Botões do menu
        options = {
            "Sistema": self.show_sistema,
            "Personalização": self.show_personalizacao,
            "Aplicações": self.show_aplicacoes,
            "Atualizações": self.show_atualizacoes
        }

        for text, command in options.items():
            btn = tk.Button(sidebar, text=text, font=("Segoe UI", 11),
                            relief="flat", anchor="w", bg="#e6e6e6",
                            activebackground="#d4d4d4", command=command)
            btn.pack(fill="x", pady=2, padx=5)

        # Mostrar a primeira página por defeito
        self.show_sistema()

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def show_sistema(self):
        self.clear_content()
        tk.Label(self.content, text="Definições de Sistema", font=("Segoe UI", 16), bg="white").pack(pady=20)
        tk.Label(self.content, text="Aqui aparecem opções como Som, Ecrã, Energia...", bg="white").pack()

    def show_personalizacao(self):
        self.clear_content()
        tk.Label(self.content, text="Personalização", font=("Segoe UI", 16), bg="white").pack(pady=20)
        tk.Label(self.content, text="Fundo, cores, temas, ecrã de bloqueio...", bg="white").pack()

    def show_aplicacoes(self):
        self.clear_content()
        tk.Label(self.content, text="Aplicações", font=("Segoe UI", 16), bg="white").pack(pady=20)
        tk.Label(self.content, text="Programas instalados, apps predefinidas...", bg="white").pack()

    def show_atualizacoes(self):
        self.clear_content()
        tk.Label(self.content, text="Atualizações e Segurança", font=("Segoe UI", 16), bg="white").pack(pady=20)
        tk.Label(self.content, text="Windows Update, segurança, backups...", bg="white").pack()

if __name__ == "__main__":
    app = App()
    app.mainloop()
