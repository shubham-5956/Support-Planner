import { Outlet } from "react-router-dom";

export default function CommonLayout(){
    return <div>
        <div>Common Header</div>
        <main className="relative mx-auto max-w-6xl px-4 py-8">
            <Outlet/>
        </main>
    </div>
}