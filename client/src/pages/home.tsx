import { useState, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Eye,
  MessageCircleWarning,
  Brain,
  ChevronDown,
  ChevronUp,
  BookOpen,
  Lightbulb,
  Search,
  Sparkles,
  Sun,
  Moon,
  ImageIcon,
  Upload,
  X,
  FileText,
  Info,
  Skull,
  Banknote,
  Fingerprint,
  Crosshair,
  EyeOff,
} from "lucide-react";
import {
  analyzeContent,
  exampleScenarios,
  type AnalysisResult,
  type Detection,
  type RiskLevel,
  type Scenario,
} from "@/lib/analysis-engine";
import {
  analyzeImage,
  type ImageAnalysisResult,
  type ImageDetection,
  type ImageRiskLevel,
} from "@/lib/image-analysis-engine";
import { useTheme } from "@/components/ThemeProvider";
import { PerplexityAttribution } from "@/components/PerplexityAttribution";

const riskConfig: Record<
  RiskLevel,
  { label: string; color: string; bgColor: string; borderColor: string; icon: typeof Shield }
> = {
  critico: {
    label: "Critico",
    color: "text-red-600 dark:text-red-400",
    bgColor: "bg-red-50 dark:bg-red-950/30",
    borderColor: "border-red-200 dark:border-red-800/40",
    icon: ShieldAlert,
  },
  alto: {
    label: "Alto",
    color: "text-orange-600 dark:text-orange-400",
    bgColor: "bg-orange-50 dark:bg-orange-950/30",
    borderColor: "border-orange-200 dark:border-orange-800/40",
    icon: AlertTriangle,
  },
  medio: {
    label: "Medio",
    color: "text-amber-600 dark:text-amber-400",
    bgColor: "bg-amber-50 dark:bg-amber-950/30",
    borderColor: "border-amber-200 dark:border-amber-800/40",
    icon: AlertTriangle,
  },
  bajo: {
    label: "Bajo",
    color: "text-teal-600 dark:text-teal-400",
    bgColor: "bg-teal-50 dark:bg-teal-950/20",
    borderColor: "border-teal-200 dark:border-teal-800/40",
    icon: ShieldCheck,
  },
  seguro: {
    label: "Seguro",
    color: "text-emerald-600 dark:text-emerald-400",
    bgColor: "bg-emerald-50 dark:bg-emerald-950/20",
    borderColor: "border-emerald-200 dark:border-emerald-800/40",
    icon: ShieldCheck,
  },
};

const categoryConfig: Record<
  string,
  { label: string; icon: typeof Shield; color: string }
> = {
  emocional: {
    label: "Riesgo Emocional",
    icon: Brain,
    color: "text-purple-600 dark:text-purple-400",
  },
  privacidad: {
    label: "Privacidad",
    icon: Eye,
    color: "text-blue-600 dark:text-blue-400",
  },
  grooming: {
    label: "Anti-Grooming",
    icon: MessageCircleWarning,
    color: "text-red-600 dark:text-red-400",
  },
  deepfake: {
    label: "Anti-Deepfake",
    icon: Sparkles,
    color: "text-amber-600 dark:text-amber-400",
  },
};

function RiskMeter({ score, risk }: { score: number; risk: RiskLevel }) {
  const config = riskConfig[risk];
  const RiskIcon = config.icon;
  const percentage = Math.min(score, 100);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle
            cx="60"
            cy="60"
            r="50"
            fill="none"
            stroke="hsl(var(--border))"
            strokeWidth="8"
          />
          <circle
            cx="60"
            cy="60"
            r="50"
            fill="none"
            stroke={
              risk === "critico"
                ? "hsl(var(--destructive))"
                : risk === "alto"
                ? "hsl(25, 90%, 50%)"
                : risk === "medio"
                ? "hsl(40, 90%, 50%)"
                : "hsl(var(--primary))"
            }
            strokeWidth="8"
            strokeDasharray={`${(percentage / 100) * 314} 314`}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <RiskIcon className={`w-6 h-6 ${config.color}`} />
          <span className={`text-lg font-bold ${config.color}`}>
            {score}%
          </span>
        </div>
      </div>
      <Badge
        variant="outline"
        className={`${config.color} ${config.bgColor} ${config.borderColor} font-semibold px-3 py-1`}
      >
        Riesgo {config.label}
      </Badge>
    </div>
  );
}

function DetectionCard({ detection }: { detection: Detection }) {
  const [expanded, setExpanded] = useState(false);
  const risk = riskConfig[detection.riskLevel];
  const cat = categoryConfig[detection.category];
  const CatIcon = cat.icon;

  return (
    <div
      className={`rounded-lg border ${risk.borderColor} ${risk.bgColor} p-4 transition-all duration-200`}
    >
      <div
        className="flex items-start justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        data-testid={`detection-toggle-${detection.id}`}
      >
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <div className={`mt-0.5 ${cat.color}`}>
            <CatIcon className="w-5 h-5" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="font-semibold text-sm">{detection.title}</h4>
              <Badge
                variant="outline"
                className={`${risk.color} text-xs shrink-0`}
              >
                {risk.label}
              </Badge>
            </div>
            {detection.matchedText && (
              <p className="text-xs text-muted-foreground mt-1 truncate">
                Detectado:{" "}
                <span className="font-mono bg-muted px-1 rounded">
                  "{detection.matchedText}"
                </span>
              </p>
            )}
          </div>
        </div>
        <button className="shrink-0 ml-2 p-1 rounded hover:bg-muted/50 transition-colors" aria-label="Expandir detalles">
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-4 h-4 text-muted-foreground" />
          )}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 space-y-3 pl-8 text-sm">
          <div className="space-y-1">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <AlertTriangle className="w-3.5 h-3.5" />
              Por que es riesgoso
            </div>
            <p className="text-muted-foreground leading-relaxed">
              {detection.explanation}
            </p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <ShieldCheck className="w-3.5 h-3.5" />
              Que hacer
            </div>
            <p className="text-muted-foreground leading-relaxed">
              {detection.recommendation}
            </p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <BookOpen className="w-3.5 h-3.5" />
              Aprende mas
            </div>
            <p className="text-muted-foreground leading-relaxed italic">
              {detection.learnMore}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function ScenarioCard({
  scenario,
  onSelect,
}: {
  scenario: Scenario;
  onSelect: (text: string) => void;
}) {
  const catColors: Record<string, string> = {
    emocional: "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300",
    privacidad: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300",
    grooming: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300",
    deepfake: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300",
    mixto: "bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300",
  };

  return (
    <button
      onClick={() => onSelect(scenario.text)}
      className="text-left p-3 rounded-lg border border-border/60 hover:border-primary/40 hover:bg-muted/50 transition-all duration-200 group"
      data-testid={`scenario-${scenario.id}`}
    >
      <div className="flex items-center gap-2 mb-1">
        <Badge variant="outline" className={`text-xs ${catColors[scenario.category]}`}>
          {scenario.category === "mixto" ? "Combinado" : categoryConfig[scenario.category]?.label}
        </Badge>
      </div>
      <h4 className="font-semibold text-sm group-hover:text-primary transition-colors">
        {scenario.title}
      </h4>
      <p className="text-xs text-muted-foreground mt-0.5">
        {scenario.description}
      </p>
    </button>
  );
}

function CategorySummary({ detections }: { detections: Detection[] }) {
  const categories = ["emocional", "privacidad", "grooming", "deepfake"] as const;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
      {categories.map((cat) => {
        const config = categoryConfig[cat];
        const CatIcon = config.icon;
        const count = detections.filter((d) => d.category === cat).length;

        return (
          <div
            key={cat}
            className={`flex items-center gap-2 p-2.5 rounded-lg border transition-all duration-200 ${
              count > 0
                ? "border-border bg-muted/50"
                : "border-border/40 opacity-50"
            }`}
          >
            <CatIcon className={`w-4 h-4 shrink-0 ${config.color}`} />
            <div className="min-w-0">
              <p className="text-xs font-medium truncate">{config.label}</p>
              <p className="text-xs text-muted-foreground">
                {count} alerta{count !== 1 ? "s" : ""}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── IMAGE ANALYSIS COMPONENTS ───
const imageCategoryConfig: Record<string, { label: string; icon: typeof Shield; color: string }> = {
  privacidad: { label: "Privacidad", icon: Fingerprint, color: "text-blue-600 dark:text-blue-400" },
  estafa: { label: "Estafa", icon: Banknote, color: "text-orange-600 dark:text-orange-400" },
  violencia: { label: "Violencia", icon: Skull, color: "text-red-600 dark:text-red-400" },
  armas: { label: "Armas", icon: Crosshair, color: "text-gray-700 dark:text-gray-300" },
  desnudos: { label: "Desnudos", icon: EyeOff, color: "text-pink-600 dark:text-pink-400" },
  metadatos: { label: "Metadatos", icon: Info, color: "text-cyan-600 dark:text-cyan-400" },
  deepfake: { label: "Deepfake", icon: Sparkles, color: "text-amber-600 dark:text-amber-400" },
};

function ImageDetectionCard({ detection }: { detection: ImageDetection }) {
  const [expanded, setExpanded] = useState(false);
  const risk = riskConfig[detection.riskLevel];
  const cat = imageCategoryConfig[detection.category] || imageCategoryConfig.estafa;
  const CatIcon = cat.icon;

  return (
    <div className={`rounded-lg border ${risk.borderColor} ${risk.bgColor} p-4 transition-all duration-200`}>
      <div
        className="flex items-start justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <div className={`mt-0.5 ${cat.color}`}>
            <CatIcon className="w-5 h-5" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="font-semibold text-sm">{detection.title}</h4>
              <Badge variant="outline" className={`${risk.color} text-xs shrink-0`}>
                {risk.label}
              </Badge>
            </div>
            {detection.detail && (
              <p className="text-xs text-muted-foreground mt-1 truncate">
                <span className="font-mono bg-muted px-1 rounded">{detection.detail}</span>
              </p>
            )}
          </div>
        </div>
        <button className="shrink-0 ml-2 p-1 rounded hover:bg-muted/50 transition-colors">
          {expanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 space-y-3 pl-8 text-sm">
          <div className="space-y-1">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <AlertTriangle className="w-3.5 h-3.5" /> Por que es riesgoso
            </div>
            <p className="text-muted-foreground leading-relaxed">{detection.explanation}</p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <ShieldCheck className="w-3.5 h-3.5" /> Que hacer
            </div>
            <p className="text-muted-foreground leading-relaxed">{detection.recommendation}</p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <BookOpen className="w-3.5 h-3.5" /> Aprende mas
            </div>
            <p className="text-muted-foreground leading-relaxed italic">{detection.learnMore}</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Home() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const { theme, toggle } = useTheme();

  // Image analysis state
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [imageResult, setImageResult] = useState<ImageAnalysisResult | null>(null);
  const [isAnalyzingImage, setIsAnalyzingImage] = useState(false);
  const [imageProgress, setImageProgress] = useState(0);
  const [imageStatus, setImageStatus] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleAnalyze = () => {
    if (!text.trim()) return;
    setIsAnalyzing(true);
    // Small delay to show loading state
    setTimeout(() => {
      const analysis = analyzeContent(text);
      setResult(analysis);
      setIsAnalyzing(false);
    }, 600);
  };

  const handleScenario = (scenarioText: string) => {
    setText(scenarioText);
    setResult(null);
  };

  const handleClear = () => {
    setText("");
    setResult(null);
  };

  // Image handlers
  const handleImageSelect = useCallback((file: File) => {
    if (!file.type.startsWith("image/")) return;
    setImageFile(file);
    setImageResult(null);
    setImageProgress(0);
    setImageStatus("");
    const reader = new FileReader();
    reader.onload = (e) => setImagePreview(e.target?.result as string);
    reader.readAsDataURL(file);
  }, []);

  const handleImageAnalyze = async () => {
    if (!imageFile) return;
    setIsAnalyzingImage(true);
    setImageProgress(0);
    try {
      const result = await analyzeImage(imageFile, (progress, status) => {
        setImageProgress(progress);
        setImageStatus(status);
      });
      setImageResult(result);
    } catch (err) {
      console.error("Error analyzing image:", err);
    } finally {
      setIsAnalyzingImage(false);
    }
  };

  const handleImageClear = () => {
    setImageFile(null);
    setImagePreview(null);
    setImageResult(null);
    setImageProgress(0);
    setImageStatus("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleImageSelect(file);
  }, [handleImageSelect]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border/60 bg-background/95 backdrop-blur-sm">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <Shield className="w-4.5 h-4.5 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight">CiberShield</h1>
              <p className="text-xs text-muted-foreground leading-none">
                Filtro educativo de seguridad
              </p>
            </div>
          </div>
          <button
            onClick={toggle}
            className="p-2 rounded-lg hover:bg-muted transition-colors"
            aria-label={`Cambiar a modo ${theme === "dark" ? "claro" : "oscuro"}`}
            data-testid="theme-toggle"
          >
            {theme === "dark" ? (
              <Sun className="w-4 h-4" />
            ) : (
              <Moon className="w-4 h-4" />
            )}
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Intro */}
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <h2 className="text-lg font-bold">
            Analiza contenido antes de publicar
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Pega o escribe el texto de una publicacion, mensaje o chat. CiberShield
            detectara riesgos emocionales, de privacidad, patrones de grooming y
            amenazas de deepfake, explicandote por que algo es peligroso.
          </p>
        </div>

        {/* Main Content */}
        <Tabs defaultValue="analyzer" className="space-y-4">
          <TabsList className="grid w-full max-w-lg mx-auto grid-cols-3">
            <TabsTrigger value="analyzer" data-testid="tab-analyzer">
              <Search className="w-3.5 h-3.5 mr-1.5" />
              Texto
            </TabsTrigger>
            <TabsTrigger value="image" data-testid="tab-image">
              <ImageIcon className="w-3.5 h-3.5 mr-1.5" />
              Imagen
            </TabsTrigger>
            <TabsTrigger value="scenarios" data-testid="tab-scenarios">
              <Lightbulb className="w-3.5 h-3.5 mr-1.5" />
              Escenarios
            </TabsTrigger>
          </TabsList>

          <TabsContent value="analyzer" className="space-y-4">
            {/* Input Area */}
            <Card>
              <CardContent className="p-4 space-y-3">
                <Textarea
                  placeholder="Pega aqui el texto de una publicacion, mensaje directo, o conversacion de chat que quieras analizar..."
                  value={text}
                  onChange={(e) => {
                    setText(e.target.value);
                    if (result) setResult(null);
                  }}
                  className="min-h-[140px] resize-y text-sm"
                  data-testid="input-text"
                />
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs text-muted-foreground">
                    {text.length} caracteres
                  </p>
                  <div className="flex gap-2">
                    {text && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleClear}
                        data-testid="button-clear"
                      >
                        Limpiar
                      </Button>
                    )}
                    <Button
                      size="sm"
                      onClick={handleAnalyze}
                      disabled={!text.trim() || isAnalyzing}
                      data-testid="button-analyze"
                    >
                      {isAnalyzing ? (
                        <>
                          <div className="w-3.5 h-3.5 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin mr-1.5" />
                          Analizando...
                        </>
                      ) : (
                        <>
                          <Shield className="w-3.5 h-3.5 mr-1.5" />
                          Analizar
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Results */}
            {result && (
              <div className="space-y-4" data-testid="analysis-results">
                {/* Risk Overview */}
                <Card>
                  <CardContent className="p-5">
                    <div className="flex flex-col sm:flex-row items-center gap-6">
                      <RiskMeter score={result.score} risk={result.overallRisk} />
                      <div className="flex-1 text-center sm:text-left space-y-3">
                        <div>
                          <h3 className="font-bold text-base">
                            Resultado del Analisis
                          </h3>
                          <p className="text-sm text-muted-foreground leading-relaxed mt-1">
                            {result.summary}
                          </p>
                        </div>
                        <CategorySummary detections={result.detections} />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Detections */}
                {result.detections.length > 0 && (
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-bold flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        Alertas detectadas ({result.detections.length})
                      </CardTitle>
                      <p className="text-xs text-muted-foreground">
                        Haz clic en cada alerta para ver la explicacion educativa
                        completa
                      </p>
                    </CardHeader>
                    <CardContent className="space-y-2 pt-0">
                      {result.detections.map((d) => (
                        <DetectionCard key={d.id} detection={d} />
                      ))}
                    </CardContent>
                  </Card>
                )}

                {/* Educational Summary */}
                <Card className="border-primary/20 bg-primary/5">
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      <BookOpen className="w-5 h-5 text-primary mt-0.5 shrink-0" />
                      <div className="space-y-1.5">
                        <h4 className="font-semibold text-sm">
                          Nota Educativa
                        </h4>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                          Este filtro es una herramienta educativa basada en
                          patrones de texto. En un entorno real, los sistemas de
                          deteccion utilizan inteligencia artificial, analisis de
                          contexto, procesamiento de lenguaje natural (NLP) y redes
                          neuronales para detectar riesgos con mayor precision.
                          Este simulador te ayuda a entender que tipo de contenido
                          puede ser peligroso y por que.
                        </p>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                          Categorias de analisis: deteccion de riesgo emocional,
                          privacidad visual, anti-grooming y anti-deepfake.
                          Cada deteccion incluye una explicacion de por que algo
                          es riesgoso, que hacer al respecto, y contenido
                          educativo adicional.
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          {/* IMAGE ANALYSIS TAB */}
          <TabsContent value="image" className="space-y-4">
            <Card>
              <CardContent className="p-4 space-y-3">
                {/* Drop Zone / Upload */}
                {!imagePreview ? (
                  <div
                    onDrop={handleDrop}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onClick={() => fileInputRef.current?.click()}
                    className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-200 ${
                      isDragging
                        ? "border-primary bg-primary/5"
                        : "border-border/60 hover:border-primary/40 hover:bg-muted/30"
                    }`}
                  >
                    <Upload className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
                    <p className="text-sm font-medium">Arrastra una imagen aqui o haz clic para seleccionar</p>
                    <p className="text-xs text-muted-foreground mt-1">Soporta JPG, PNG, GIF, WebP</p>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/*"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) handleImageSelect(file);
                      }}
                    />
                  </div>
                ) : (
                  <div className="space-y-3">
                    {/* Image Preview */}
                    <div className="relative rounded-lg overflow-hidden border border-border/60 bg-muted/30">
                      <img
                        src={imagePreview}
                        alt="Preview"
                        className="w-full max-h-[300px] object-contain"
                      />
                      <button
                        onClick={handleImageClear}
                        className="absolute top-2 right-2 p-1.5 bg-background/80 rounded-full hover:bg-background border border-border/60 transition-colors"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">
                        {imageFile?.name} ({(imageFile?.size ? imageFile.size / 1024 : 0).toFixed(0)} KB)
                      </p>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm" onClick={handleImageClear}>
                          Cambiar
                        </Button>
                        <Button
                          size="sm"
                          onClick={handleImageAnalyze}
                          disabled={isAnalyzingImage}
                        >
                          {isAnalyzingImage ? (
                            <>
                              <div className="w-3.5 h-3.5 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin mr-1.5" />
                              Analizando...
                            </>
                          ) : (
                            <>
                              <Shield className="w-3.5 h-3.5 mr-1.5" />
                              Analizar imagen
                            </>
                          )}
                        </Button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Progress Bar */}
                {isAnalyzingImage && (
                  <div className="space-y-1.5">
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-primary h-2 rounded-full transition-all duration-300"
                        style={{ width: `${imageProgress}%` }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground text-center">{imageStatus}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Image Results */}
            {imageResult && (
              <div className="space-y-4">
                {/* Risk Overview */}
                <Card>
                  <CardContent className="p-5">
                    <div className="flex flex-col sm:flex-row items-center gap-6">
                      <RiskMeter score={imageResult.score} risk={imageResult.overallRisk} />
                      <div className="flex-1 text-center sm:text-left space-y-3">
                        <div>
                          <h3 className="font-bold text-base">Resultado del Analisis de Imagen</h3>
                          <p className="text-sm text-muted-foreground leading-relaxed mt-1">
                            {imageResult.summary}
                          </p>
                        </div>
                        {/* Category summary */}
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                          {Object.entries(imageCategoryConfig).map(([cat, config]) => {
                            const CatIcon = config.icon;
                            const count = imageResult.detections.filter((d) => d.category === cat).length;
                            return (
                              <div
                                key={cat}
                                className={`flex items-center gap-2 p-2.5 rounded-lg border transition-all duration-200 ${
                                  count > 0 ? "border-border bg-muted/50" : "border-border/40 opacity-50"
                                }`}
                              >
                                <CatIcon className={`w-4 h-4 shrink-0 ${config.color}`} />
                                <div className="min-w-0">
                                  <p className="text-xs font-medium truncate">{config.label}</p>
                                  <p className="text-xs text-muted-foreground">{count} alerta{count !== 1 ? "s" : ""}</p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Extracted Text */}
                {imageResult.extractedText && (
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-bold flex items-center gap-2">
                        <FileText className="w-4 h-4" /> Texto detectado en la imagen (OCR)
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="bg-muted/50 rounded-lg p-3 text-xs font-mono whitespace-pre-wrap max-h-[150px] overflow-y-auto">
                        {imageResult.extractedText}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Metadata */}
                {imageResult.metadata && Object.keys(imageResult.metadata).length > 0 && (
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-bold flex items-center gap-2">
                        <Info className="w-4 h-4" /> Metadatos de la imagen
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                        {Object.entries(imageResult.metadata).filter(([k]) => k !== "Texto detectado").map(([key, value]) => (
                          <div key={key} className="text-xs">
                            <span className="text-muted-foreground">{key}:</span>{" "}
                            <span className="font-medium">{value}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Detections */}
                {imageResult.detections.length > 0 && (
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-bold flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        Alertas detectadas ({imageResult.detections.length})
                      </CardTitle>
                      <p className="text-xs text-muted-foreground">
                        Haz clic en cada alerta para ver la explicacion educativa
                      </p>
                    </CardHeader>
                    <CardContent className="space-y-2 pt-0">
                      {imageResult.detections.map((d) => (
                        <ImageDetectionCard key={d.id} detection={d} />
                      ))}
                    </CardContent>
                  </Card>
                )}

                {/* Educational Note */}
                <Card className="border-primary/20 bg-primary/5">
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      <BookOpen className="w-5 h-5 text-primary mt-0.5 shrink-0" />
                      <div className="space-y-1.5">
                        <h4 className="font-semibold text-sm">Nota Educativa</h4>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                          Este analizador extrae texto de imagenes mediante OCR (Reconocimiento
                          Optico de Caracteres) y examina metadatos y patrones visuales.
                          Detecta estafas, datos personales expuestos, contenido violento
                          e indicadores de deepfake. En produccion, se complementaria con
                          modelos de vision por computadora para un analisis mas profundo.
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          <TabsContent value="scenarios" className="space-y-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-bold">
                  Escenarios de ejemplo
                </CardTitle>
                <p className="text-xs text-muted-foreground">
                  Selecciona un escenario predefinido para ver como funciona el
                  analisis. Cada uno representa una situacion real de riesgo en
                  redes sociales.
                </p>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {exampleScenarios.map((s) => (
                    <ScenarioCard
                      key={s.id}
                      scenario={s}
                      onSelect={(t) => {
                        handleScenario(t);
                        // Switch to analyzer tab
                        const analyzerTab = document.querySelector(
                          '[data-testid="tab-analyzer"]'
                        ) as HTMLButtonElement;
                        analyzerTab?.click();
                      }}
                    />
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Educational Categories */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <Brain className="w-5 h-5 text-purple-500 mt-0.5 shrink-0" />
                    <div>
                      <h4 className="font-semibold text-sm">Riesgo Emocional</h4>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        Detecta expresiones de vulnerabilidad emocional,
                        ideacion suicida, amenazas, y senales de acoso que
                        pueden indicar riesgo para el usuario o ser
                        aprovechadas por depredadores.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <Eye className="w-5 h-5 text-blue-500 mt-0.5 shrink-0" />
                    <div>
                      <h4 className="font-semibold text-sm">
                        Privacidad Visual
                      </h4>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        Identifica datos personales expuestos: ubicacion,
                        telefono, datos financieros, credenciales, informacion
                        de menores, y patrones que revelan ausencia del hogar.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <MessageCircleWarning className="w-5 h-5 text-red-500 mt-0.5 shrink-0" />
                    <div>
                      <h4 className="font-semibold text-sm">Anti-Grooming</h4>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        Reconoce las fases del grooming: halagos manipuladores,
                        secretismo, solicitud de material visual, intentos de
                        encuentro, indagacion de edad y contenido sexualizado.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <Sparkles className="w-5 h-5 text-amber-500 mt-0.5 shrink-0" />
                    <div>
                      <h4 className="font-semibold text-sm">Anti-Deepfake</h4>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        Alerta sobre contenido deepfake: videos manipulados,
                        solicitudes de face swap, voz clonada, suplantacion
                        de identidad digital, y comparte tecnicas de
                        verificacion.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/40 mt-12 py-6">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 text-center space-y-2">
          <p className="text-xs text-muted-foreground">
            CiberShield es una herramienta educativa. No sustituye el juicio
            humano ni sistemas de seguridad profesionales.
          </p>
          <PerplexityAttribution />
        </div>
      </footer>
    </div>
  );
}
