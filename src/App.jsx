import React, { useState, useRef, useEffect } from 'react';
import { 
  Upload, 
  AlertTriangle, 
  CheckCircle2, 
  FileText, 
  X, 
  Loader2,
  ChevronRight,
  Sun,
  Moon,
  Trash2,
  ShieldAlert,
  Terminal,
  FileCode,
  ClipboardCheck,
  Clipboard,
  Eye,
  ShieldCheck,
  Search,
  Zap,
  Download,
  FileSearch,
  ScanEye
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import * as pdfjsLib from 'pdfjs-dist';
import pdfWorker from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import confetti from 'canvas-confetti';
import JSZip from 'jszip';
import { renderAsync } from 'docx-preview';
import { cn } from './lib/utils';

// Set up PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;

const SUSPICIOUS_KEYWORDS = [
  'ignore previous instructions',
  'system prompt',
  'hidden instruction',
  'jailbreak',
  'do anything now',
  'ignore all rules',
  'forgot about previous',
  'actually move in',
  'instead of',
  'new instructions'
];

// Sub-component for DOCX rendering
const DocxPreview = ({ file, theme }) => {
  const containerRef = useRef(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (file && containerRef.current) {
      const render = async () => {
        try {
          const arrayBuffer = await file.arrayBuffer();
          containerRef.current.innerHTML = "";
          await renderAsync(arrayBuffer, containerRef.current, null, {
            className: "docx-render",
            inWrapper: false,
            ignoreWidth: false,
            ignoreHeight: false,
          });
        } catch (e) {
          console.error("DOCX Preview failed", e);
          setError(true);
        }
      };
      render();
    }
  }, [file]);

  if (error) return (
    <div className="h-full flex flex-col items-center justify-center p-8 text-center text-zinc-500">
      <AlertTriangle size={32} className="mb-4 text-orange-500" />
      <p className="text-xs font-black uppercase">Preview Failed</p>
    </div>
  );

  return (
    <div ref={containerRef} className={cn("docx-wrapper mx-auto max-w-full min-h-full p-4 md:p-8", theme === 'light' ? "docx-light" : "docx-dark")} />
  );
};

export default function App() {
  const [file, setFile] = useState(null);
  const [fileUrl, setFileUrl] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [progress, setProgress] = useState(0);
  const [rightPanel, setRightPanel] = useState('findings'); 
  const [theme, setTheme] = useState(() => localStorage.getItem('docshield_theme') || 'dark');
  const [copied, setCopied] = useState(false);
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [mobileView, setMobileView] = useState('doc'); // 'doc' or 'analysis'
  const fileInputRef = useRef(null);

  useEffect(() => {
    localStorage.setItem('docshield_theme', theme);
    document.documentElement.className = theme;
  }, [theme]);

  const sanitizeText = (text) => {
    let sanitized = text;
    SUSPICIOUS_KEYWORDS.forEach(keyword => {
      const regex = new RegExp(keyword, 'gi');
      sanitized = sanitized.replace(regex, '[REMOVED]');
    });
    return sanitized;
  };

  const highlightRiskyText = (text, issues) => {
    if (!text || !issues) return text;
    const flagSnippets = issues.map(issue => issue.context).filter(Boolean);
    const allFlags = [...new Set([...SUSPICIOUS_KEYWORDS, ...flagSnippets])].sort((a,b) => b.length - a.length);
    const escaped = allFlags.map(f => f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const regex = new RegExp(`(${escaped.join('|')})`, 'gi');

    return text.split(regex).map((part, i) => {
      const isMatch = allFlags.some(flag => flag.toLowerCase() === part.toLowerCase());
      return isMatch ? (
        <mark key={i} className="bg-red-500/30 text-red-500 border-b-2 border-red-500 font-black px-1 rounded-sm animate-pulse-slow">
          {part}
        </mark>
      ) : part;
    });
  };

  const processFile = (selectedFile) => {
    if (selectedFile) {
      if (fileUrl) URL.revokeObjectURL(fileUrl);
      const url = URL.createObjectURL(selectedFile);
      setFileUrl(url);
      setFile(selectedFile);
      
      if (selectedFile.type === 'application/pdf' || selectedFile.name.endsWith('.pdf')) {
        processPdf(selectedFile);
      } else if (selectedFile.name.endsWith('.docx')) {
        processDocx(selectedFile);
      }
    }
  };

  const processPdf = async (pdfFile) => {
    setIsScanning(true);
    setScanResult(null);
    setProgress(0);

    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const typedarray = new Uint8Array(e.target.result);
        const pdf = await pdfjsLib.getDocument(typedarray).promise;
        
        let foundIssues = [];
        let fullText = "";
        const numPages = pdf.numPages;

        for (let i = 1; i <= numPages; i++) {
          setProgress(Math.round((i / numPages) * 100));
          const page = await pdf.getPage(i);
          const textContent = await page.getTextContent();
          
          let pageText = "";
          textContent.items.forEach((item) => {
            pageText += item.str + " ";
            const text = item.str.toLowerCase();
            const fontSize = Math.abs(item.transform[0]); 

            SUSPICIOUS_KEYWORDS.forEach(keyword => {
              if (text.includes(keyword.toLowerCase())) {
                foundIssues.push({
                  id: Math.random(),
                  type: 'Injection Keyword',
                  detail: `Blocked phrase: "${keyword}"`,
                  context: item.str,
                  page: i,
                  severity: 'high'
                });
              }
            });

            if (fontSize > 0 && fontSize < 4 && text.trim().length > 0) {
              foundIssues.push({
                id: Math.random(),
                type: 'Hidden Text',
                detail: `Micro-text caught (Size: ${fontSize.toFixed(1)})`,
                context: item.str,
                page: i,
                severity: 'medium'
              });
            }
          });

          fullText += pageText + "\n\n";
        }
        finishScan(foundIssues, numPages, fullText, pdfFile);
      };
      reader.readAsArrayBuffer(pdfFile);
    } catch (error) {
      setIsScanning(false);
    }
  };

  const processDocx = async (docxFile) => {
    setIsScanning(true);
    setScanResult(null);
    setProgress(10);

    try {
      const arrayBuffer = await docxFile.arrayBuffer();
      const zip = await JSZip.loadAsync(arrayBuffer);
      const documentXml = await zip.file("word/document.xml").async("string");
      
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(documentXml, "text/xml");
      
      let foundIssues = [];
      let fullText = "";
      const textNodes = xmlDoc.getElementsByTagName("w:r");
      
      setProgress(50);

      for (let i = 0; i < textNodes.length; i++) {
        const rNode = textNodes[i];
        const tNodes = rNode.getElementsByTagName("w:t");
        if (tNodes.length === 0) continue;

        const text = Array.from(tNodes).map(node => node.textContent).join("");
        fullText += text + " ";
        const rPr = rNode.getElementsByTagName("w:rPr")[0];
        
        let isWhite = false, isMicro = false;
        if (rPr) {
          const color = rPr.getElementsByTagName("w:color")[0];
          if (color) {
            const colorVal = (color.getAttribute("w:val") || "").toUpperCase();
            if (colorVal === "FFFFFF" || colorVal === "FFFFFF00") isWhite = true;
          }
          const sz = rPr.getElementsByTagName("w:sz")[0];
          if (sz) {
            const szVal = parseInt(sz.getAttribute("w:val"));
            if (szVal <= 8) isMicro = true; // Sz is double points, so 4pt = 8sz
          }
        }

        if (isWhite && text.trim().length > 0) {
          foundIssues.push({
            id: Math.random(),
            type: 'Hidden Text',
            detail: `White-on-white text detected`,
            context: text,
            page: 1,
            severity: 'high'
          });
        }
        if (isMicro && text.trim().length > 0) {
          foundIssues.push({
            id: Math.random(),
            type: 'Micro-text',
            detail: `Suspiciously small font size`,
            context: text,
            page: 1,
            severity: 'medium'
          });
        }

        SUSPICIOUS_KEYWORDS.forEach(keyword => {
          if (text.toLowerCase().includes(keyword.toLowerCase())) {
            foundIssues.push({ 
              id: Math.random(), 
              type: 'Injection Keyword', 
              detail: `Malicious command phrase`, 
              context: text, 
              page: 1, 
              severity: 'high' 
            });
          }
        });
      }
      setProgress(100);
      finishScan(foundIssues, 1, fullText, docxFile);
    } catch (error) {
      setIsScanning(false);
    }
  };

  const finishScan = (foundIssues, pageCount, rawText, sourceFile) => {
    const isEmpty = rawText.trim().length === 0;
    
    setTimeout(() => {
      setIsScanning(false);
      setScanResult({
        safe: foundIssues.length === 0 && !isEmpty,
        issues: foundIssues,
        pageCount: pageCount,
        fileName: sourceFile.name,
        rawText: rawText,
        sanitizedText: sanitizeText(rawText),
        isEmpty: isEmpty
      });
      if (foundIssues.length === 0 && !isEmpty) {
        confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 }, colors: ['#ffffff', '#C3FF00'] });
      }
    }, 800);
  };

  const copyToClipboard = () => {
    if (scanResult?.sanitizedText) {
      navigator.clipboard.writeText(scanResult.sanitizedText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const reset = () => {
    if (fileUrl) URL.revokeObjectURL(fileUrl);
    setFile(null);
    setFileUrl(null);
    setScanResult(null);
    setIsScanning(false);
    setSelectedIssue(null);
    setRightPanel('findings');
    setMobileView('doc');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const isLight = theme === 'light';

  return (
    <div className={cn("h-screen w-screen flex flex-col items-center py-4 px-6 overflow-hidden transition-colors duration-300", isLight ? "bg-[#F9FAFB] text-zinc-950" : "bg-black text-white")}>
      <div className="w-full max-w-5xl h-full flex flex-col space-y-4">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:justify-between md:items-center shrink-0 gap-4 md:h-16">
           <div className="flex items-center justify-between w-full md:w-auto">
              <div className="flex items-center gap-3">
                 <img src="/logo.svg" alt="DocShit Logo" className="w-8 h-8 md:w-10 md:h-10" />
                 <h2 className="text-lg md:text-xl font-bold uppercase tracking-widest mt-1">docshit</h2>
              </div>
              {/* Mobile MobileView Toggle */}
              {scanResult && (
                <div className={cn("md:hidden flex p-1 border transition-colors", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900")}>
                  <button onClick={() => setMobileView('doc')} className={cn("px-3 py-1 text-[8px] font-black uppercase transition-all", mobileView === 'doc' ? "bg-[#C3FF00] text-black" : "text-zinc-500 hover:text-zinc-400")}><Eye size={14} /></button>
                  <button onClick={() => setMobileView('analysis')} className={cn("px-3 py-1 text-[8px] font-black uppercase transition-all", mobileView === 'analysis' ? "bg-[#C3FF00] text-black" : "text-zinc-500 hover:text-zinc-400")}><Search size={14} /></button>
                </div>
              )}
           </div>
           
           <div className="flex flex-wrap items-center gap-2 md:gap-4 w-full md:w-auto justify-between md:justify-end">
              {scanResult && (
                <div className={cn("flex p-1 border transition-colors flex-1 md:flex-initial justify-center", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900")}>
                  {['findings', 'safe-text', 'extracted-text'].map((mode) => (
                    <button 
                      key={mode}
                      onClick={() => { setRightPanel(mode); setMobileView('analysis'); }}
                      className={cn(
                        "flex-1 md:flex-initial px-2 md:px-4 py-1.5 text-[8px] md:text-[9px] font-black uppercase tracking-widest transition-all", 
                        rightPanel === mode 
                          ? "bg-[#C3FF00] text-black" 
                          : "text-zinc-500 hover:text-zinc-300"
                      )}
                    >
                      {mode === 'extracted-text' ? 'Proof' : mode.replace('-', ' ').split(' ')[0]}
                    </button>
                  ))}
                </div>
              )}

              <div className="flex gap-2">
                <div className={cn("flex p-1 transition-colors border", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900")}>
                  <button onClick={() => setTheme('light')} className={cn("p-1.5 md:p-2 transition-all", isLight ? "bg-zinc-100 text-black shadow-sm" : "text-zinc-500 hover:text-zinc-300")}><Sun size={16} /></button>
                  <button onClick={() => setTheme('dark')} className={cn("p-1.5 md:p-2 transition-all", !isLight ? "bg-zinc-800 text-white shadow-sm" : "text-zinc-500 hover:text-zinc-300")}><Moon size={16} /></button>
                </div>
                <button onClick={reset} className={cn("p-2 md:p-2.5 border transition-all hover:scale-95", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900")}><Trash2 size={18} /></button>
                <label className={cn("p-2 md:p-2.5 border cursor-pointer flex items-center justify-center transition-all hover:scale-95", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900")}>
                   <Upload size={18} />
                   <input type="file" className="hidden" accept=".pdf,.docx" onChange={(e) => processFile(e.target.files[0])} />
                </label>
              </div>
           </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 min-h-0 overflow-hidden">
          <AnimatePresence mode="wait">
          {isScanning ? (
            <motion.div key="scanning" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="h-full flex flex-col items-center justify-center space-y-8">
               <div className={cn("p-8 border-2 border-dashed relative flex items-center justify-center transition-colors", isLight ? "border-zinc-200" : "border-zinc-800")}>
                  <Loader2 size={64} className="animate-spin text-[#C3FF00] opacity-20" />
                  <img src="/logo.svg" alt="DocShit Logo" className="w-8 h-8 absolute animate-pulse-slow object-contain" />
               </div>
               <div className="text-center space-y-2">
                  <h3 className="text-xl font-black uppercase tracking-widest">Scanning</h3>
                  <p className="text-sm font-bold text-zinc-500">{progress}% Analyzed</p>
               </div>
            </motion.div>
          ) : scanResult ? (
            <motion.div key="result" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="h-full flex flex-col space-y-4">
              {/* Header Stats */}
              <div className={cn("shrink-0 flex flex-col md:flex-row md:justify-between md:items-end pb-4 border-b transition-colors gap-4", isLight ? "border-zinc-200" : "border-zinc-800")}>
                <div>
                  <p className="text-[9px] md:text-[10px] font-black uppercase tracking-widest text-zinc-500 mb-1">Source Analysis</p>
                  <h2 className={cn("text-lg md:text-2xl font-black uppercase tracking-tight truncate max-w-[300px] md:max-w-none", scanResult.isEmpty ? "text-orange-500" : (scanResult.safe ? "text-emerald-500" : "text-red-500"))}>{scanResult.fileName}</h2>
                </div>
                <div className="flex items-center gap-2 md:gap-4">
                   <div className={cn("border px-3 md:px-4 py-1.5 md:py-2 transition-colors flex-1 md:flex-initial md:min-w-[150px]", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900")}>
                      <p className="text-[8px] md:text-[9px] font-black uppercase text-zinc-500 block">Status</p>
                      <span className={cn("text-[10px] md:text-xs font-black", scanResult.isEmpty ? "text-orange-500" : (scanResult.safe ? "text-emerald-500" : "text-red-500"))}>
                        {scanResult.isEmpty ? "Empty" : `${scanResult.issues.length} Risks`}
                      </span>
                   </div>
                   {rightPanel === 'safe-text' && !scanResult.isEmpty && (
                      <button onClick={copyToClipboard} className={cn("h-full px-4 md:px-6 py-2 border border-[#C3FF00] font-black uppercase text-[9px] md:text-[10px] transition-all bg-[#C3FF00] text-black hover:bg-[#b0e600] flex-1 md:flex-initial", copied ? "bg-emerald-500 border-emerald-500 text-white" : "")}>
                        {copied ? "Copied" : "Copy"}
                     </button>
                   )}
                </div>
              </div>

              {/* Main Split Layout */}
              <div className="flex-1 min-h-0 grid md:grid-cols-[1.2fr_0.8fr] gap-6 pb-2">
                <div className={cn("flex-col space-y-3 min-h-0", mobileView === 'doc' ? 'flex' : 'hidden md:flex')}>
                  <div className="flex items-center justify-between shrink-0">
                    <h2 className="text-[10px] font-black uppercase tracking-widest text-zinc-500">Document Browser</h2>
                    <span className="text-[9px] font-black uppercase opacity-30">{file?.name.endsWith('.pdf') ? 'PDF' : 'DOCX'}</span>
                  </div>
                  <div className={cn("flex-1 border overflow-hidden relative transition-colors", isLight ? "bg-white border-zinc-200" : "bg-black border-zinc-900 text-black")}>
                    {file?.name.endsWith('.pdf') ? (
                      <iframe key={fileUrl} src={`${fileUrl}#toolbar=0&navpanes=0`} className="w-full h-full border-none" title="PDF Preview" />
                    ) : (
                      <div className="w-full h-full overflow-auto no-scrollbar scroll-smooth">
                        <DocxPreview file={file} theme={theme} />
                      </div>
                    )}
                  </div>
                </div>

                <div className={cn("flex-col space-y-3 min-h-0", mobileView === 'analysis' ? 'flex' : 'hidden md:flex')}>
                   <div className="flex items-center justify-between shrink-0 h-6">
                      <h2 className="text-[10px] font-black uppercase tracking-widest">{rightPanel.replace('-', ' ')}</h2>
                   </div>
                   <div className="flex-1 min-h-0">
                      <AnimatePresence mode="wait">
                        {scanResult.isEmpty ? (
                          <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className={cn("h-full border border-dashed flex flex-col items-center justify-center p-8 text-center", isLight ? "border-orange-200 bg-orange-50/30" : "border-orange-900/30 bg-orange-500/5")}>
                             <ScanEye size={48} className="text-orange-500 mb-6" />
                             <h3 className="text-sm font-black uppercase text-orange-500 mb-2">OCR Failure / Image Data</h3>
                             <p className="text-[10px] font-bold text-zinc-500 max-w-[240px] leading-relaxed">
                               This document contains no selectable text. It likely consists of <span className="text-orange-500">handwritten notes</span>, <span className="text-orange-500">scanned images</span>, or vectors. Sanitization cannot be performed.
                             </p>
                          </motion.div>
                        ) : rightPanel === 'findings' ? (
                          <motion.div key="findings" initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }} className="h-full overflow-y-auto no-scrollbar space-y-2">
                             {scanResult.issues.length > 0 ? scanResult.issues.map((issue, idx) => (
                               <div key={idx} onClick={() => setSelectedIssue(issue)} className={cn("p-3 border flex items-center justify-between cursor-pointer transition-all group", isLight ? "border-zinc-200 bg-white hover:border-zinc-300" : "border-zinc-800 bg-zinc-900/50 hover:border-zinc-700")}>
                                  <div className="flex items-center gap-4 min-w-0">
                                     <div className={cn("w-10 h-10 flex items-center justify-center shrink-0", issue.severity === 'high' ? "bg-red-500/10 text-red-500" : "bg-orange-500/10 text-orange-500")}><ShieldAlert size={16} /></div>
                                     <div className="truncate">
                                        <h4 className="text-[11px] font-black uppercase truncate">{issue.detail}</h4>
                                        <span className="text-[8px] font-black opacity-50 uppercase tracking-widest">{issue.type} • P{issue.page}</span>
                                     </div>
                                  </div>
                                  <ChevronRight className="w-4 h-4 opacity-50 group-hover:translate-x-1 transition-transform" />
                               </div>
                             )) : (
                               <div className={cn("h-full flex flex-col items-center justify-center border-2 border-dashed transition-colors", isLight ? "border-zinc-200" : "border-zinc-800")}><CheckCircle2 size={32} className="text-emerald-500 mb-4" /><h3 className="font-black text-sm uppercase opacity-50">Safe</h3></div>
                             )}
                          </motion.div>
                        ) : rightPanel === 'safe-text' ? (
                          <motion.div key="safe" initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }} className="h-full flex flex-col space-y-3">
                             <div className={cn("flex-1 p-4 border font-mono text-[11px] leading-relaxed overflow-y-auto no-scrollbar transition-colors", isLight ? "border-zinc-200 bg-white text-zinc-600" : "border-zinc-800 bg-zinc-950 text-emerald-400/80")}>
                                {scanResult.sanitizedText}
                             </div>
                             <div className={cn("p-3 border border-dashed text-[8px] font-black uppercase leading-tight", isLight ? "bg-emerald-50 border-emerald-200 text-emerald-700" : "bg-emerald-500/5 border-emerald-900/30 text-emerald-500")}>
                                Hijacking risks and hidden gaps neutralized. Ready for LLM input.
                             </div>
                          </motion.div>
                        ) : (
                          <motion.div key="proof" initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }} className={cn("h-full border p-4 font-mono text-[11px] overflow-y-auto no-scrollbar whitespace-pre-wrap transition-colors leading-relaxed", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900", "text-zinc-500")}>
                             {highlightRiskyText(scanResult.rawText, scanResult.issues)}
                          </motion.div>
                        )}
                      </AnimatePresence>
                   </div>
                </div>
              </div>
            </motion.div>
          ) : (
            <motion.div key="home" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="h-full flex items-center justify-center">
               <div className="max-w-md w-full text-center space-y-8">
                  <div className="space-y-4">
                     <img src="/logo.svg" alt="DocShit Logo" className="w-24 h-24 mx-auto mb-2 object-contain drop-shadow-2xl" />
                     <div className="space-y-1">
                        <h1 className="text-4xl font-black uppercase tracking-widest mt-6">DocShit</h1>
                        <p className="text-xs font-black uppercase tracking-[0.15em] opacity-50">Sanitize your LLM inputs.</p>
                     </div>
                  </div>
                  <label className={cn("flex items-center justify-center gap-3 w-full py-5 border-2 border-[#C3FF00] cursor-pointer transition-all active:scale-95 font-black text-xs uppercase tracking-widest bg-[#C3FF00] text-black hover:bg-[#b0e600]")}>
                     <Upload size={18} /><span>Upload File</span>
                     <input type="file" className="hidden" accept=".pdf,.docx" onChange={(e) => processFile(e.target.files[0])} />
                  </label>
                  <div className="grid grid-cols-2 gap-4">
                     <div className={cn("p-4 border text-left transition-colors", isLight ? "border-zinc-200 bg-zinc-50" : "border-zinc-800 bg-zinc-900")}>
                        <h4 className="text-[9px] font-black mb-1 uppercase opacity-50">Deep Scan</h4>
                        <p className="text-[10px] font-black leading-tight">Full structure analysis.</p>
                     </div>
                     <div className={cn("p-4 border text-left transition-colors", isLight ? "border-zinc-200 bg-zinc-50" : "border-zinc-800 bg-zinc-900")}>
                        <h4 className="text-[9px] font-black mb-1 uppercase opacity-50">Privacy</h4>
                        <p className="text-[10px] font-black leading-tight">No data uploads.</p>
                     </div>
                  </div>
               </div>
            </motion.div>
          )}
          </AnimatePresence>
        </div>

        {/* Footer */}
        <div className="flex justify-center items-center py-2 shrink-0 border-t border-transparent">
          <p className="text-[9px] md:text-[10px] font-black uppercase tracking-widest">
            made with love by <a href="https://theajmlarazaq.github.io" target="_blank" rel="noopener noreferrer" className="hover:text-[#a098ff] hover:opacity-100 transition-all underline decoration-dotted underline-offset-4">ajmal razaq bhatti</a>
          </p>
        </div>

        {/* Modal */}
        <AnimatePresence>
        {selectedIssue && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
             <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="absolute inset-0 bg-black/60 backdrop-blur-md" onClick={() => setSelectedIssue(null)} />
             <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className={cn("relative w-full max-w-2xl p-8 space-y-6 border shadow-2xl transition-colors", isLight ? "border-zinc-200 bg-white" : "border-zinc-800 bg-zinc-900")}>
                <div className="flex justify-between items-start">
                   <div className="flex items-center gap-4">
                      <img src="/logo.svg" alt="DS" className="w-12 h-12 object-contain" />
                      <div>
                         <span className={cn("text-[8px] font-black uppercase border px-2 py-0.5", isLight ? "border-zinc-200 text-zinc-400" : "border-zinc-700 text-zinc-500")}>
                           {selectedIssue.type} • P{selectedIssue.page}
                         </span>
                         <h2 className="text-xl font-black uppercase mt-1 text-red-500">Threat Fragment</h2>
                      </div>
                   </div>
                   <button onClick={() => setSelectedIssue(null)} className="text-zinc-500 hover:text-red-500 transition-colors"><X size={20} /></button>
                </div>
                <div className={cn("p-4 border font-mono text-xs whitespace-pre-wrap overflow-auto max-h-40 transition-colors", isLight ? "bg-zinc-50 border-zinc-200 text-red-600" : "bg-black border-zinc-800 text-red-400")}>
                  "{selectedIssue.context}"
                </div>
                <button onClick={() => setSelectedIssue(null)} className={cn("w-full py-4 border-2 border-[#C3FF00] font-black uppercase text-xs transition-all bg-[#C3FF00] text-black hover:bg-[#b0e600]")}>Close</button>
             </motion.div>
          </div>
        )}
        </AnimatePresence>
      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .docx-wrapper { width: 100%; min-height: 100%; }
        .docx-render { background: transparent !important; margin: 0 auto !important; width: 100% !important; padding: 0 !important; }
        .docx-render section { background: white !important; padding: 40px !important; margin-bottom: 20px !important; box-shadow: 0 10px 30px rgba(0,0,0,0.1) !important; color: black !important; }
        .docx-dark .docx-render section { background: #09090b !important; color: #f4f4f5 !important; border: 1px solid #27272a !important; box-shadow: none !important; }
        .docx-dark .docx-render p, .docx-dark .docx-render span, .docx-dark .docx-render h1, .docx-dark .docx-render h2, .docx-dark .docx-render h3, .docx-dark .docx-render li, .docx-dark .docx-render td { color: #f4f4f5 !important; background-color: transparent !important; }
        .docx-dark .docx-render table { border-color: #27272a !important; }
        .docx-render p, .docx-render span, .docx-render h1, .docx-render h2, .docx-render h3 { color: inherit !important; }
        @keyframes pulse-slow { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        .animate-pulse-slow { animation: pulse-slow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
      `}} />
    </div>
  );
}
