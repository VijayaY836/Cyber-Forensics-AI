# 🔧 QUICK TROUBLESHOOTING GUIDE

---

## 🚨 EMERGENCY FIXES (During Hackathon)

### **App Won't Start**

**Error:** `ModuleNotFoundError`
```bash
# Fix: Reinstall dependencies
pip install -r requirements.txt

# Or install individually:
pip install streamlit pandas scikit-learn networkx plotly numpy matplotlib
```

**Error:** `Port already in use`
```bash
# Fix: Use different port
streamlit run app.py --server.port 8502
```

---

### **CSS Not Loading (Dark Theme Missing)**

**Symptoms:** White background, no green colors

**Quick Fix:**
1. Check `assets/style.css` exists
2. In `app.py`, verify line ~17:
   ```python
   with open("assets/style.css") as f:
   ```
3. If file missing, recreate it from Step 3.1
4. Restart Streamlit

---

### **Charts Not Displaying**

**Symptoms:** Blank spaces where charts should be

**Quick Fix:**
```bash
# Reinstall Plotly
pip uninstall plotly
pip install plotly==5.18.0
```

**Alternative:** Check browser console (F12) for JavaScript errors

---

### **"Invalid property 'titlefont'" Error**

**Already Fixed!** If you still see this:

1. Open `utils/visualization.py`
2. Search for `titlefont_size`
3. Replace with:
   ```python
   title=dict(
       text='Title Here',
       font=dict(size=20, color='#00ff41')
   )
   ```

---

### **Anomaly Detection Takes Forever**

**Symptoms:** Spinner runs for 30+ seconds

**Quick Fix:**
- Reduce contamination factor to 0.05
- Use smaller dataset for demo
- Close other apps to free memory

---

### **Session State Lost**

**Symptoms:** Data disappears when navigating

**Quick Fix:**
1. **DON'T** refresh browser during demo
2. If data lost, re-run from Upload Logs
3. Keep terminal open at all times

---

### **File Upload Fails**

**Symptoms:** Error parsing CSV

**Quick Fix:**
1. Verify CSV has headers
2. Check for special characters
3. Use sample file: `data/sample_logs.csv`
4. Try JSON format: `data/sample_logs.json`

---

### **Graph Visualization Empty**

**Symptoms:** "No correlated events to display"

**Reasons:**
1. No anomalies detected (increase contamination)
2. Time window too small (increase to 60 min)
3. Events too far apart in time

**Fix:** Adjust parameters or use enhanced sample data

---

## 🐛 COMMON ERRORS & SOLUTIONS

### **Error: "No module named 'modules'"**

**Cause:** Missing `__init__.py` files

**Fix:**
```bash
touch modules/__init__.py
touch utils/__init__.py
```

Or create empty files in VS Code

---

### **Error: "KeyError: 'anomaly_score'"**

**Cause:** Trying to correlate before anomaly detection

**Fix:** Always run in order:
1. Upload Logs
2. Anomaly Detection
3. Event Correlation
4. Timeline Analysis
5. Report Generation

---

### **Error: "'NoneType' object has no attribute"**

**Cause:** Session state variable not initialized

**Fix:** Check `app.py` lines 24-31 for initialization

---

### **Warning: "Deprecated Plotly syntax"**

**Safe to Ignore** - Functionality works fine

**If Annoying:** Update Plotly to latest:
```bash
pip install --upgrade plotly
```

---

## 💻 SYSTEM-SPECIFIC ISSUES

### **Windows: Python not found**

```bash
# Use py instead of python
py -m streamlit run app.py
```

### **Mac: Permission Denied**

```bash
# Fix permissions
chmod +x app.py
python3 -m streamlit run app.py
```

### **Linux: Display issues**

```bash
# Set display variable
export DISPLAY=:0
streamlit run app.py
```

---

## 🔍 DEBUGGING TIPS

### **Enable Streamlit Debug Mode**

Add to `app.py`:
```python
st.set_option('deprecation.showPyplotGlobalUse', False)
```

### **Check Terminal Output**

Look for:
- Import errors
- Deprecation warnings
- Exception tracebacks

### **Browser Console (F12)**

Check for:
- JavaScript errors
- Failed resource loads
- Network issues

### **Test Individual Modules**

```bash
# Test log parser
python -c "from modules.log_parser import parse_logs; print('OK')"

# Test anomaly detector
python -c "from modules.anomaly_detector import detect_anomalies; print('OK')"
```

---

## ⚡ PERFORMANCE OPTIMIZATION

### **Slow Startup**

**Solution:** Reduce imports
- Import modules only when needed
- Use lazy loading for heavy libraries

### **Memory Issues**

**Solution:**
```python
# Add to app.py after imports
import gc
gc.collect()  # Force garbage collection
```

### **Slow Charts**

**Solution:** Reduce data points
```python
# In visualization functions
df_sample = df.sample(min(1000, len(df)))
```

---

## 📱 PRESENTATION SETUP

### **Projector Display Issues**

1. **Resolution:** Set browser zoom to 125%
2. **Font Size:** Increase in settings
3. **Contrast:** Dark theme helps readability

### **WiFi Fails During Demo**

**Backup Plan:**
1. Take screenshots of each step
2. Have pre-generated report as PDF
3. Use local sample data (no internet needed)

### **Laptop Freezes**

**Prevention:**
- Close all other apps
- Disable auto-updates
- Have backup laptop ready
- Test on presentation device beforehand

---

## 🆘 NUCLEAR OPTION

**If Everything Breaks:**

1. **Have backup screenshots** of working demo
2. **Show code instead** - walk through architecture
3. **Explain approach** - judges value problem-solving
4. **Stay confident** - technical issues happen

---

## 📞 LAST-MINUTE CHECKLIST

**5 Minutes Before Demo:**

- [ ] App running and loaded
- [ ] Sample file ready to upload
- [ ] Browser in full screen
- [ ] Notifications disabled
- [ ] Battery charged
- [ ] WiFi connected
- [ ] Terminal visible
- [ ] Backup plan ready

---

## 🎓 LEARNING FROM ERRORS

**If something fails:**
1. Stay calm
2. Explain what should happen
3. Show code solution
4. Judges appreciate problem-solving

**Remember:** Judges want to see:
- Your understanding
- Your approach
- Your debugging skills

---

## 💪 YOU GOT THIS!

Most issues have simple fixes. Take a deep breath, follow this guide, and trust your preparation!

**Good luck! 🚀🏆**