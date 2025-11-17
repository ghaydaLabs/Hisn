import tkinter as tk
from tkinter import ttk, messagebox
# استيراد الدوال المنطقية من ملف auditor.py
from auditor import check_strength, check_pwned, generate_secure_password, analyze_hash, calculate_entropy 

class PasswordAuditorApp:
    def __init__(self, master):
        self.master = master
        master.title("Password Auditor & PenTest Tool")
        master.geometry("600x450")

        # إنشاء نظام التبويبات
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")
        
        # إنشاء التبويبات
        self.tab_single_check = ttk.Frame(self.notebook)
        self.tab_hash_analysis = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_single_check, text='🔍 فحص كلمة مرور واحدة')
        self.notebook.add(self.tab_hash_analysis, text='🔑 تحليل التجزئة (Hash)')

        self._create_single_check_tab(self.tab_single_check)
        self._create_hash_analysis_tab(self.tab_hash_analysis)

    # ------------------------------------
    # واجهة تبويب فحص كلمة المرور
    # ------------------------------------
    def _create_single_check_tab(self, tab):
        ttk.Label(tab, text="أدخل كلمة المرور للفحص:").pack(pady=10)
        
        # حقل إدخال كلمة المرور (مع زر لإظهار/إخفاء النص)
        self.password_entry = ttk.Entry(tab, width=40, show="*")
        self.password_entry.pack(pady=5)
        
        self.show_pass_var = tk.StringVar(value="Show")
        ttk.Button(tab, textvariable=self.show_pass_var, command=self._toggle_password_visibility).pack(pady=5)
        
        ttk.Button(tab, text="تحليل كلمة المرور", command=self._run_single_check).pack(pady=10)
        
        # منطقة عرض النتائج (Text widget)
        self.results_text = tk.Text(tab, height=12, width=65, state=tk.DISABLED)
        self.results_text.pack(pady=10, padx=10)

    def _toggle_password_visibility(self):
        # وظيفة إظهار/إخفاء كلمة المرور
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
            self.show_pass_var.set("Hide")
        else:
            self.password_entry.config(show='*')
            self.show_pass_var.set("Show")

    def _run_single_check(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("تنبيه", "الرجاء إدخال كلمة مرور للفحص.")
            return

        # 1. استدعاء الدوال من auditor.py
        score, reasons = check_strength(password)
        entropy = calculate_entropy(password)
        status, count = check_pwned(password)

        # 2. تنسيق النتائج للعرض
        output = f"--- تقرير كلمة المرور: {password} ---\n\n"
        output += f"1. تقييم القوة (Score {score}/4):\n"
        if score == 4:
            output += "   ✅ كلمة المرور قوية جداً.\n"
        else:
            output += "   ⚠️ ضعيفة/متوسطة: \n" + "\n".join([f"   - {r}" for r in reasons]) + "\n"
            
        output += f"\n2. مقياس العشوائية (Entropy):\n   {entropy} Bits"
        if entropy < 60:
             output += " 🚨 (تحذير: Entropy منخفضة جدًا)\n"
        else:
            output += "\n"
            
        output += f"\n3. فحص الاختراق (Breach Check):\n"
        if status == "Breached":
            output += f"   🚨 خطر! تم العثور عليها {count} مرة في قواعد البيانات المخترقة.\n"
        elif status == "Safe":
            output += "   ✅ لم يتم العثور عليها في الاختراقات العامة.\n"
        else:
            output += f"   ❌ حدث خطأ في الاتصال بالـ API.\n"
        
        # 3. عرض النتائج في منطقة النص
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, output)
        self.results_text.config(state=tk.DISABLED)
        
    # ------------------------------------
    # واجهة تبويب تحليل التجزئة (Hash)
    # ------------------------------------
    def _create_hash_analysis_tab(self, tab):
        ttk.Label(tab, text="أدخل التجزئة (Hash) لتحليلها:").pack(pady=10)
        
        self.hash_entry = ttk.Entry(tab, width=50)
        self.hash_entry.pack(pady=5)
        ttk.Button(tab, text="تحليل التجزئة أمنياً", command=self._run_hash_analysis).pack(pady=10)
        
        self.hash_results_text = tk.Text(tab, height=8, width=65, state=tk.DISABLED)
        self.hash_results_text.pack(pady=10, padx=10)

    def _run_hash_analysis(self):
        hash_str = self.hash_entry.get()
        if not hash_str:
            messagebox.showwarning("تنبيه", "الرجاء إدخال تجزئة للتحليل.")
            return
            
        # 1. استدعاء دالة analyze_hash من auditor.py
        hash_type, analysis, strength = analyze_hash(hash_str)
        
        # 2. تنسيق النتائج للعرض
        output = f"--- تحليل التجزئة الأمنية ---\n"
        output += f"نوع التجزئة المُحتمل: {hash_type}\n"
        output += f"تقييم القوة: {strength}\n\n"
        output += f"التحليل الأمني:\n{analysis}"

        # 3. عرض النتائج
        self.hash_results_text.config(state=tk.NORMAL)
        self.hash_results_text.delete(1.0, tk.END)
        self.hash_results_text.insert(tk.END, output)
        self.hash_results_text.config(state=tk.DISABLED)

# --- نقطة البداية ---
if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordAuditorApp(root)
    root.mainloop()
